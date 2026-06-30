# Reading the policy in detail

This page documents exactly how `passwolf policy` reads the Active Directory password policy. It covers the ten read methods, the wire technique behind each, the change-failure oracle technique, the domain versus PSO scope distinction, how each value is labelled with the official Group Policy field name, the per-method reachability map, and the Server 2025 difference. The implementation lives in `src/passwolf/policy.py` (one function per wire method), with the normalized records in `src/passwolf/policymodel.py` and the orchestration in `src/passwolf/pwpolicy.py`. For the operator-facing command, see [the passwolf policy guide](../guide/policy.md); for the wire crypto these methods reuse, see [Crypto and password buffers](crypto.md); for how the SAMR channel is opened, see [Transport and channels](transport.md). The one-line summary of all ten methods is in [the method matrix](../methods.md).

## The ten read methods

`passwolf policy` reads the policy over ten distinct channels. Each runs independently and records its own reachability verdict, so a single run shows which channels leaked the policy and which were denied rather than collapsing to one answer. The method ids below are the exact `--method` choices the tool exposes (`all` runs every method).

| `--method` | Channel and opnum | Spec | Scope |
|---|---|---|---|
| `samr-query` | SAMR QueryInformationDomain2 (opnum 46, opnum 8 fallback), classes 1/12/3 | [MS-SAMR] 3.1.5.5.1, 3.1.5.5.2 | domain: length, history, ages, properties, lockout, force-logoff |
| `samr-getdompwinfo` | SAMR GetDomainPasswordInformation (opnum 56) | [MS-SAMR] 3.1.5.13.2 | domain, handle-light: length and properties |
| `samr-getusrpwinfo` | SAMR GetUserDomainPasswordInformation (opnum 44) | [MS-SAMR] 3.1.5.13.1 | per-user, PSO-effective: length and properties |
| `samr-diag` | SAMR UnicodeChangePasswordUser3 (opnum 63), used as an oracle | leaked samrpc.idl (line 1550), undocumented in [MS-SAMR] | per-user, PSO-effective: full DOMAIN_PASSWORD_INFORMATION plus failure reason |
| `kpasswd` | Kerberos kpasswd (port 464) SOFTERROR blob | RFC 3244 | per-user, PSO-effective: length, history, ages, flags |
| `ldap-domain-head` | LDAP domainDNS password attributes | [MS-ADTS] 3.1.1.4 | domain, most complete single read |
| `ldap-pso` | LDAP Password Settings Container objects | [MS-ADTS] 6.1.1.4.11.1 | every PSO, complexity and reversible as explicit booleans (values ACL-gated) |
| `ldap-resultant` | LDAP msDS-ResultantPSO (constructed attribute) | [MS-ADTS] 3.1.1.4.5.36 | the winning PSO DN for the subject, dereferenced |
| `ldap-uac` | LDAP msDS-User-Account-Control-Computed | [MS-ADTS] 3.1.1.4.5.17 | subject lockout and expiry state, plus bad-password count |
| `sysvol` | SMB SYSVOL GptTmpl.inf security templates | [MS-GPSB] 2.2.1 | configured intent per GPO, cross-checking the live values |

## SAMR domain-query classes (samr-query)

`samr_password_policy()` builds the default-domain policy from three DOMAIN_INFORMATION_CLASS queries against an open domain handle: class 1 (DomainPasswordInformation) for the password fields, class 12 (DomainLockoutInformation) for lockout, and class 3 (DomainLogoffInformation) for force-logoff. The handle is opened once over the standard SamrConnect, SamrEnumerateDomainsInSamServer, SamrLookupDomainInSamServer, SamrOpenDomain chain in `open_domain_handle()`, skipping the builtin domain so the account domain is queried.

Each class goes through `_query_domain()`, which calls SamrQueryInformationDomain2 (opnum 46) first and falls back to SamrQueryInformationDomain (opnum 8) on an RPC fault. Both opnums return the same SAMPR_DOMAIN_INFO_BUFFER union, so opnum 46 is the modern call and opnum 8 the legacy one, and trying 46 then 8 covers every server version per [MS-SAMR] 3.1.5.5.1 and 3.1.5.5.2.

Class 1 is required and raises through if denied. The lockout (class 12) and force-logoff (class 3) reads are best-effort: if either faults, the password fields still return. This is the authenticated, complete default-policy read over SAMR, gated by DOMAIN_READ_PASSWORD_PARAMETERS on the domain handle.

!!! note "Tick conversion"
    Classes 1 and 3 carry their ages as split OLD_LARGE_INTEGER values (LowPart and HighPart), read back to a signed 100-nanosecond tick count by `_old_li_ticks()` per [MS-SAMR] 2.2.2.2 (OLD_LARGE_INTEGER), the SAMR delta-time fields. Class 12 carries NDRHYPER values, reinterpreted as signed by `_hyper_signed()`. A magnitude at or above int64-max is the never sentinel and is reported as infinity. Ages normalize to days, lockout windows to minutes, force-logoff to seconds. See [Crypto and password buffers](crypto.md) for the delta-time interval handling shared across methods.

## SAMR handle-light getter (samr-getdompwinfo)

`samr_get_domain_password_information()` calls SamrGetDomainPasswordInformation (opnum 56), which needs no domain handle: the server resolves the account domain itself. It is therefore reachable before any OpenDomain, making it the lightest policy probe, but it carries only the minimum password length and the PasswordProperties bitmask per [MS-SAMR] 3.1.5.13.2.

!!! warning "Spec versus reality on anonymous access"
    The spec describes opnum 56 as obtaining policy information without authenticating to the server. On modern domain controllers a null-session caller is refused with STATUS_ACCESS_DENIED, while any authenticated principal (including a low-privilege user) succeeds. The operative property is no special privilege required, not no authentication required, because modern Windows restricts anonymous SAMR. `passwolf policy` records that denial in the reachability map rather than treating opnum 56 as an unauthenticated read.

## SAMR per-user getter (samr-getusrpwinfo)

`samr_get_user_password_information()` calls SamrGetUserDomainPasswordInformation (opnum 44). It opens the target account with USER_READ_GENERAL, then asks the server for the policy it considers effective for that user. Because the server resolves the effective policy, a fine-grained password policy (PSO) bound to the user is reflected here, unlike the default-domain classes. Like opnum 56 it carries only length and properties, per [MS-SAMR] 3.1.5.13.1. This method is tagged `scope="PSO"` and is one of the `--target-user` methods: it resolves an arbitrary named account's effective policy without that account's secret, because it opens and queries the object rather than proving a change.

## The change-failure oracle (samr-diag and kpasswd)

Two methods, `samr-diag` and `kpasswd`, are change-failure oracles. They do not read a policy attribute. Instead they submit a password change that is guaranteed to be rejected, and read the effective policy out of the server's rejection. The technique is identical for both; only the wire protocol differs.

### The oracle technique

A single probe password is shared by both oracles in `policy.py`:

```python
# A new password guaranteed to violate any real domain policy (too short, and zero complexity classes),
# so the opnum-63 and kpasswd oracles always draw STATUS_PASSWORD_RESTRICTION / SOFTERROR and the probed
# account is never actually changed.
_POLICY_PROBE_PASSWORD = "\x01\x01"
```

The probe is two control characters: two bytes long, with zero complexity classes (no upper, lower, digit, or symbol). It violates any real domain minimum-length and complexity requirement, so the server always rejects it before any write. Three properties make this a safe read:

- The account is never changed. The new password always fails policy, so the server returns its rejection and applies nothing.
- The effective policy comes back inside the rejection. Both protocols carry the policy the server enforced as part of the failure response, which is the policy effective for the authenticating principal (PSO-aware).
- An unexpected success is reported as a failure. If the probe somehow succeeds, the password may have been applied, so `passwolf policy` raises an error telling the operator to verify the account rather than silently accepting a write.

Because both oracles prove identity by attempting a self-change, they prove identity as the authenticating principal and report that principal's effective policy. They require a non-anonymous bind, and an anonymous run skips them. To read a specific account's PSO-effective policy through the oracles, authenticate as that account.

### samr-diag: opnum 63

`samr_oracle_policy()` drives SamrUnicodeChangePasswordUser3 (opnum 63). This method is undocumented in [MS-SAMR], which marks opnum 63 as reserved for local use; the NDR stub is built from the leaked Windows IDL (samrpc.idl line 1550) in `src/passwolf/ndr.py`. It sits between SamrUnicodeChangePasswordUser2 (opnum 55) and SamrUnicodeChangePasswordUser4 (opnum 73, [MS-SAMR] 3.1.5.10.4) and uniquely returns two extra out-parameters: EffectivePasswordPolicy (a DOMAIN_PASSWORD_INFORMATION block) and PasswordChangeInfo (a USER_PWD_CHANGE_FAILURE_INFORMATION structure carrying ExtendedFailureReason).

The wire crypto is the same RC4 SAMPR_USER_PASSWORD buffer plus DES NT-OWF verifier as opnum 55: the probe is encrypted under the account's current NT hash (`build_rc4_password_buffer`), and the old NT hash is DES-encrypted under the new NT hash as the verifier. The call uses `dce.call()` and `dce.recv()` directly rather than the auto-raising helper, so impacket's status auto-raise does not discard the diagnostics body. On a real rejection the server fills EffectivePasswordPolicy with the full DOMAIN_PASSWORD_INFORMATION (min length, history, both ages, and the properties bitmask) and sets ExtendedFailureReason; on a success the policy block comes back null (it is populated only to explain a rejection). `samr-diag` is tagged `scope="PSO"`.

??? note "Why opnum 63 returns the effective policy on success as null"
    On Server 2022 and earlier the probe is rejected with STATUS_PASSWORD_RESTRICTION and the EffectivePasswordPolicy referent is populated. If the referent comes back as a null block, the method distinguishes two cases: a STATUS_ACCESS_DENIED status (the Server 2025 gate, surfaced as the method being unavailable) and any other status (reported as an operation failure, since the probe drew no password restriction). The ExtendedFailureReason is captured but kept diagnostic only; it is not rendered in the policy tables.

### kpasswd: the SOFTERROR blob

`kpasswd_softerror_policy()` runs the same probe over Kerberos kpasswd (port 464, RFC 3244). It authenticates the bind principal against the kadmin/changepw service, submits a guaranteed-violating self-change with `createKPasswdRequest`, and parses the policy out of the KDC's reply. The reply is decoded by `_decode_kpasswd_reply_raw()`, a thin decoder that mirrors only impacket's KRB-PRIV crypto (decryption under the subkey, key usage 13) to recover the raw user-data bytes, so the structured policy can be parsed instead of impacket's pre-formatted human string. The first two bytes of the user-data are the result code.

A SUCCESS result code is treated as a failure (an unexpected write); a non-SOFTERROR result code is reported as the method being unavailable with no policy blob. On a SOFTERROR the blob is parsed for the minimum length, history, both ages, and a flags list whose names map onto the identical DOMAIN_PASSWORD_* bit values. The ages arrive already in days; an age at or beyond roughly 27,000 years is the int64 never-sentinel reinterpreted and is reported as infinity. `kpasswd` is tagged `scope="PSO"`.

!!! tip "kpasswd is the oracle that survives modern hardening"
    Unlike opnum 63, the kpasswd path is not RC4-gated. It rides Kerberos message encryption and the server-side SAM change path, not the legacy RC4 SAMR password buffers, so its change/set survives on Server 2025 where opnum 63 is refused (the change/set survival is live-confirmed on Server 2025). On a modern DC the kpasswd SOFTERROR path is therefore structurally capable of carrying the effective policy where opnum 63 is refused; that policy-read oracle is spec-derived (RFC 3244) and was not live-validated in this lab.

## LDAP reads (ldap-domain-head, ldap-pso, ldap-resultant, ldap-uac)

The LDAP methods bind over sealed LDAP on 389 (SASL sign and seal, no certificate needed) by default, with `--ldaps` selecting LDAPS on 636. Each LDAP read takes its own bind in `_ldap_connect()`, supporting a password or a pass-the-hash NT hash.

### ldap-domain-head

`ldap_domain_head()` reads the default-domain policy straight off the domainDNS object at the base of the directory ([MS-ADTS] 3.1.1.4). It requests minPwdLength, pwdHistoryLength, the Interval-typed maxPwdAge and minPwdAge, pwdProperties, and the lockoutThreshold, lockoutDuration, lockOutObservationWindow, and forceLogoff attributes. These are the canonical default-domain values and are readable by any authenticated principal, which makes LDAP the most complete single-shot default-policy source. The Interval ages convert through the same `ticks_to_days` and `ticks_to_minutes` helpers as the SAMR classes.

### ldap-pso

`ldap_password_settings_objects()` enumerates every msDS-PasswordSettings object in the Password Settings Container ([MS-ADTS] 6.1.1.4.11.1). PSOs are the only source where complexity and reversible encryption are first-class booleans (msDS-PasswordComplexityEnabled, msDS-PasswordReversibleEncryptionEnabled) rather than packed PasswordProperties bits, and the only place msDS-PasswordSettingsPrecedence and the msDS-PSOAppliesTo principals are expressed.

!!! warning "PSO values are gated by the container ACL"
    The Password Settings Container is admin-readable by default. A non-privileged bind typically returns the PSO names but not their settings. `passwolf policy` detects a value-blind read (the name resolves but the length and precedence are absent) and reports that PSO with `read_status="denied"`. Seeing the PSO names but not the values is itself a useful finding, so it is surfaced rather than dropped.

### ldap-resultant

`ldap_resultant_pso()` reads msDS-ResultantPSO for the subject, a constructed attribute the DC computes that directly names the winning PSO DN ([MS-ADTS] 3.1.1.4.5.36). When the attribute is present, `passwolf policy` dereferences the DN for the PSO's values (subject to the same container ACL as `ldap-pso`). When it is absent, no PSO wins and the default domain policy governs the user. This is a `--target-user` method tagged `scope="PSO"`.

### ldap-uac

`ldap_user_account_computed()` reads msDS-User-Account-Control-Computed, a constructed attribute that carries the live UF_LOCKOUT and UF_PASSWORD_EXPIRED bits ([MS-ADTS] 3.1.1.4.5.17, bit values per 2.2.16) that the static userAccountControl does not, alongside badPwdCount. This is not a policy: it is the subject's current standing against the policy, reported under the `account` scope in the output. It is a `--target-user` method.

## SYSVOL configured intent (sysvol)

`sysvol_gpttmpl_policies()` reads the configured intent (what an admin set in Group Policy) rather than the live effective values, so it cross-checks the SAMR and LDAP reads and exposes drift or a not-yet-applied change. It opens an authenticated SMB session, lists the GPO GUID directories under `SYSVOL\<domain>\Policies`, and fetches each GPO's `MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` security template ([MS-GPSB] 2.2.1).

`_parse_gpttmpl()` decodes the template (UTF-16 with a BOM) and parses the `[System Access]` block: MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, MaximumPasswordAge, MinimumPasswordAge, ClearTextPassword, LockoutBadCount, LockoutDuration, and ResetLockoutCount. Only GPOs that actually set a `[System Access]` password key are returned, so the result lists exactly the GPOs that contribute to the configured policy. Ages in the INF are in days and lockout windows in minutes (already the canonical units); the INF `-1` sentinel maps to infinity (never).

## Domain versus PSO scope

Every record carries a `scope` so the domain-wide default and a fine-grained policy are never confused. The renderer labels each row with it.

=== "domain"

    The domain-wide default policy that governs any account without a PSO. Sources: `samr-query`, `samr-getdompwinfo`, `ldap-domain-head`. The `sysvol` configured intent is also a domain-level cross-check.

=== "PSO"

    A per-user, fine-grained effective policy that a Password Settings Object can override. Sources: `samr-getusrpwinfo` (opnum 44), `samr-diag` (opnum 63), and `kpasswd` resolve the effective policy and so reflect any PSO bound to the account; when no PSO applies, their values equal the domain default. `ldap-resultant` instead resolves the winning PSO DN (`msDS-ResultantPSO`) and reports no policy values when no PSO is bound, leaving the domain default to govern.

=== "account"

    Live account state rather than a policy. Source: `ldap-uac`, reporting lockout, expiry, and bad-password count.

The per-account methods split by what they prove. `samr-getusrpwinfo`, `ldap-resultant`, and `ldap-uac` are the three `--target-user` methods (the first two resolve the account's PSO-effective policy, `ldap-uac` reads its live account state): they resolve an arbitrary named account's fine-grained policy without its secret, because they open or query the object. `samr-diag` and `kpasswd` are the oracles: they prove identity as the authenticating principal and report that principal's own effective policy, so to read a different account through them you authenticate as that account. When `--target-user` is omitted, it defaults to the authenticating principal, so an authenticated run reads its own effective policy with no extra flag.

## Group Policy field labelling

In the detail blocks, every field is labelled with the official Microsoft Group Policy name (as it appears in secpol.msc and the Microsoft Learn password and account-lockout policy documentation), followed in parentheses by the protocol field it was read from, so the label is both admin-recognizable and traceable to the wire. For example, `Minimum password length (MinPasswordLength)`, `Reset account lockout counter after (LockoutObservationWindow)`, and for a PSO `Account lockout threshold (msDS-LockoutThreshold)`. Ages and lockout windows carry their unit in the value (`42 days`, `10 min`). The JSON format instead uses stable snake_case keys with unitless values (`minimum_password_length`, `reset_account_lockout_counter_after`), so machine consumers are never handed display text. For the full output structure see [the passwolf policy guide](../guide/policy.md).

!!! note "Default output format"
    The default output format is now `pretty` (this changed recently). `--format` also accepts `text` and `json`. The pretty and text formats open with a `methods` table (one row per method, with scope, reachability verdict, and a column for every policy field side by side), then group the detail by scope. The pretty format colors the scope column and boxes each scope into one table.

## The reachability map

The reachability map is the point of an anonymous run. Each method runs through `_attempt()` in `pwpolicy.py`, which records one of `ok`, `denied`, `unavailable: <reason>`, `failed: <reason>`, or `skipped: <reason>`, and never lets one method's failure stop another. `_classify()` distinguishes a denial (an access-denied wire error) from absence (any other failure). Two gaps are recorded as skips, not failures: the `--target-user` methods (`samr-getusrpwinfo`, `ldap-resultant`, `ldap-uac`) are skipped without a target user, and the oracle methods (`samr-diag`, `kpasswd`) are skipped on an anonymous bind because they need a principal to authenticate as.

??? note "What a null session leaks versus a low-privilege user"
    On a modern domain controller a null session is denied every SAMR policy read and cannot bind LDAP or reach SYSVOL, so nothing leaks; the map records each denial. A low-privilege authenticated user, by contrast, reads the full default policy over LDAP and SAMR and its own effective policy over the `kpasswd` and (on Server 2022) `samr-diag` oracles, and can resolve another account's PSO over opnum 44, `ldap-resultant`, and `ldap-uac` when permitted. The `ldap-pso` values are gated by the Password Settings Container ACL, so a non-privileged bind typically sees the PSO names but not their settings.

The process exit status follows from the map: `0` when at least one method returned policy data, `1` when every method was denied or unavailable, and `2` on a usage error.

## The Server 2025 difference

The two oracles draw the same effective policy by different routes, and that difference matters across server versions. Opnum 63 carries the legacy RC4 SAMR password buffer, the same wire crypto as opnum 55, so Server 2025 refuses it with STATUS_ACCESS_DENIED under the CVE-2021-33757 (KB5004605) RC4 gate that blocks the whole legacy SAMR change family (opnums 38, 54, 55, and 63). When the gate fires, `samr_oracle_policy()` raises `MethodUnavailable` and `passwolf policy` records `samr-diag` as denied:

```python
if status == STATUS_ACCESS_DENIED:  # Server 2025 gates the legacy RC4 opnum 63 (CVE-2021-33757)
    msg = "opnum 63 is refused (STATUS_ACCESS_DENIED); use kpasswd for the policy oracle on Server 2025"
    raise MethodUnavailable(msg)
```

The kpasswd SOFTERROR path is not RC4-gated. It rides Kerberos message encryption and the server-side SAM change path rather than the RC4 SAMR buffers the 2025 hardening targets, so the kpasswd channel survives on Server 2025 and the SOFTERROR path remains structurally capable of carrying the effective policy there. The opnum-63 half of this split was confirmed live: opnum 63 returns the policy on Server 2022 and STATUS_ACCESS_DENIED on Server 2025. On the kpasswd side, the Kerberos change/set was confirmed to succeed on both DCs (proving the kpasswd path survives the Server 2025 RC4 SAMR-change gate); the kpasswd SOFTERROR policy-read oracle is spec-derived (RFC 3244 and the leaked `kpasswd.cxx`) and has not yet been live-validated.

## Source map

| Concern | File |
|---|---|
| One function per wire method | `src/passwolf/policy.py` |
| Normalized records and tick or flag decoders | `src/passwolf/policymodel.py` |
| CLI, method selection, reachability orchestration | `src/passwolf/pwpolicy.py` |
| opnum-63 NDR stub from the leaked IDL | `src/passwolf/ndr.py` |
| RC4 buffer and DES OWF verifier the opnum-63 oracle reuses | `src/passwolf/crypto.py` |

See also [Reading the policy (guide)](../guide/policy.md), [Crypto and password buffers](crypto.md), [Transport and channels](transport.md), and [the method matrix](../methods.md).
