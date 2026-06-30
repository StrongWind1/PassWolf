# Method matrix

Every method is mapped to its Microsoft Open Specification section and validated against live domain controllers (Server 2022 build 20348 and Server 2025 build 26100).

## At a glance (slide-ready)

Two operations, kept strictly separate. A **change** proves your current password and sets a new one (any user, own account). A **reset** sets a new password without knowing the old one (privileged: needs the force-change-password right). The tables differ mainly in how the new password is protected on the wire and whether a Server 2025 DC still accepts them.

### Ways to change a password

| Way to change | How the new password is protected on the wire | Transport (port) | Works on Server 2025? | Notes |
|---|---|---|---|---|
| SAMR, AES (ChangePasswordUser4) | AES-256; the key is derived from your old password (PBKDF2) | RPC over SMB pipe (445), or RPC over TCP | Yes | The modern, strong one, and the only SAMR change Server 2025 allows |
| SAMR, RC4 (ChangePasswordUser2) | RC4; the key is your old NT hash | RPC over SMB pipe (445), or RPC over TCP | No (blocked) | Legacy and weak; pass-the-hash capable |
| SAMR, LM/OEM (OemChangePasswordUser2) | RC4; the key is your old LM hash | RPC over SMB pipe (445), or RPC over TCP | No (blocked) | Legacy; only works if an LM hash is stored, which is off by default today |
| SAMR, DES (ChangePasswordUser) | DES; your old and new password hashes encrypt each other | RPC over SMB pipe (445), or RPC over TCP | No (blocked) | Legacy; the only change that needs an open user handle first |
| Kerberos (kpasswd) | The whole request rides inside an encrypted Kerberos message (KRB-PRIV) | Kerberos 464 (UDP/TCP), not RPC | Yes | The standard Kerberos password change; not affected by the 2025 RC4 block |
| LDAP (modify unicodePwd) | The LDAP connection itself is encrypted (LDAPS, or LDAP sign-and-seal) | LDAP 636, or sealed 389, not RPC | Yes | The new password is just an attribute write over an already-encrypted channel |

Server 2025 blocks the three legacy SAMR changes (RC4, LM/OEM, DES) outright as part of its RC4 hardening (CVE-2021-33757 / KB5004605), leaving AES-SAMR, Kerberos, and LDAP.

### Ways to reset a password

Every SAMR reset rides one of two opnums, SamrSetInformationUser (37) or SamrSetInformationUser2 (58), and the two are interchangeable: [MS-SAMR] 3.1.5.6.5 says opnum 37 "MUST behave as with a call to SamrSetInformationUser2," and in the leaked source the body of opnum 58 is literally `return SamrSetInformationUser(...)`. What actually varies between the rows below is the info class (the UserInternal level) carried inside the request, and that info class, not the opnum, picks the cipher and what gets written.

| Way to reset | How the new password is protected on the wire | Transport (port) | Works on Server 2025? | Notes |
|---|---|---|---|---|
| SAMR, AES reset (UserInternal7 or UserInternal8) | AES-256 (AEAD); the key is the SMB session key | RPC over SMB pipe (445) only | Yes | The default modern reset. UserInternal7 sends the password alone; UserInternal8 wraps the same encrypted password in an all-information block. Identical cipher, key, and stored result; only the wire shape differs |
| SAMR, RC4 reset (UserInternal4New) | RC4 plus an MD5 salt; the key is the SMB session key | RPC over SMB pipe (445) only | Yes | Legacy cipher, but resets are not RC4-blocked on 2025. The salted (`_NEW`) form; the plain UserInternal4/5 and the 5New alias exist but passwolf does not send them |
| SAMR, set-hash (UserInternal1, or UserAllInformation) | Your raw NT (and optional LM) hash, DES-encrypted with the SMB session key | RPC over SMB pipe (445) only | Yes | Sets a hash straight from a hash; skips length, complexity, history, and minimum age (policy bypass). UserInternal1 is the dedicated hash class; UserAllInformation can carry the same NT/LM OWF fields and works remotely too |
| Kerberos (kpasswd set) | The whole request rides inside an encrypted Kerberos message (KRB-PRIV) | Kerberos 464 (UDP/TCP), not RPC | Yes | Carries the target user name and realm; the password rides as cleartext inside the Kerberos encryption |
| LDAP (replace unicodePwd) | The LDAP connection itself is encrypted (LDAPS, or LDAP sign-and-seal) | LDAP 636, or sealed 389, not RPC | Yes | A single attribute replace over an already-encrypted channel |
| DSRM (SamrSetDSRMPassword) | NT hash, DES-encrypted (keyed by the account RID) | RPC over SMB pipe (445) only | Yes | Sets the DC's local recovery account, not a domain user |

Unlike changes, **no reset is blocked on Server 2025**: the RC4 hardening targets legacy changes, not resets. Every SAMR reset is pipe-only because it borrows the SMB session key to encrypt the password buffer.

### Transport terms (pipe vs RPC over SMB)

SAMR is an MSRPC interface, so the call has to ride on top of another transport. "RPC over SMB pipe" (formally `ncacn_np`) means the RPC call travels inside an SMB named pipe called `\pipe\samr` on TCP 445; this is the same thing people loosely call "the pipe", "over SMB", or "RPC over SMB", not three different things. The only real alternative is "RPC over TCP" (formally `ncacn_ip_tcp`), where the RPC call goes straight over a TCP port (located through the endpoint mapper on 135) with no SMB and no pipe. So if you connected to `\pipe\samr`, you are using a named pipe AND SMB at the same time. SAMR changes can use either transport because they key the password buffer on your old password; SAMR resets are pipe-only because they key it on the SMB session key, which exists only over SMB. Kerberos (464) and LDAP (389/636) are their own protocols and are not RPC at all.

The legacy SAMR changes (`samr-rc4`, `samr-oem`, `samr-des`) are accepted by Server 2022 but rejected outright by Server 2025, which permits only the AES change. `passwolf change` reports the rejection cleanly and `auto` routes around it to the AES change. The `samr-oem` change additionally needs the target to store an LM hash, which NoLMHash domains (the modern default) do not.

The `samr-des` change (opnum 38) is built by hand rather than through impacket's `hSamrChangePasswordUser`, which hardcodes `LmPresent=0` and never sends the NT cross-encryption. `passwolf change` always supplies the NT authentication blobs, adds the LM authentication blobs when the cleartext old password is known (a pass-the-hash change is NT-only because the LM one-way function cannot be recovered from an NT hash), and implements the cross-encryption retry: when the account stores only one of the two hashes the server authenticates on what it has and asks for the missing new hash cross-encrypted (`STATUS_LM_CROSS_ENCRYPTION_REQUIRED` `0xC000017F` or `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` `0xC000015D`, [MS-SAMR] 3.1.5.10.1), so `passwolf change` rebuilds the request with that blob and resends. A fresh request object is built per attempt because impacket NDRCALL structs do not re-serialize cleanly after a referent field is flipped from null to a pointer. This makes `samr-des` correct on both-stored (legacy), NoLMHash (modern), and pass-the-hash changes. The NoLMHash (combination-3) case is validated live (Server 2022 `STATUS_SUCCESS`), and a single-hash LM-only change is validated live (Server 2003 and NT 4.0, direct LM-only opnum 38); the cross-encryption retry path (rebuild on `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` or `STATUS_NT_CROSS_ENCRYPTION_REQUIRED`) and the pass-the-hash change are spec and source backed but were not exercised live, since no `CROSS_ENCRYPTION_REQUIRED` status was observed on the wire.

The `samr-diag` change (opnum 63, SamrUnicodeChangePasswordUser3) is the only method that returns a machine-readable reason for a rejection. When a change fails with `STATUS_PASSWORD_RESTRICTION` the server fills two out structures in the response body: the effective `DOMAIN_PASSWORD_INFORMATION` (minimum length, history depth, minimum age) and a `USER_PWD_CHANGE_FAILURE_INFORMATION` whose extended reason is 1 for too short, 2 for in history, 5 for not complex, and 0 for too recent (minimum age). The fill is keyed purely on the top level status being `STATUS_PASSWORD_RESTRICTION` (leaked `user.c:11565-11589`), so every restriction carries the block on a modern Server 2022 DC (observed live), and because the fill is not version-conditional the legacy Server 2003 SAM is expected to behave the same; a success, a wrong old password, or the Server 2025 `ACCESS_DENIED` (observed) all return null referents. The diagnostics arrive alongside a non zero trailing status, which impacket's `request()` would raise on before the body could be read, so `passwolf change` issues the call with `call()`/`recv()` and parses the stub by hand to keep them. The reason and policy are surfaced in the `extra` block of the output. Server 2025 refuses opnum 63 outright with `STATUS_ACCESS_DENIED` (the CVE-2021-33757 legacy RC4 change gate), so the diagnostics are reachable only on Server 2022 and earlier; `auto` routes around the rejection to the AES change.

The `rap` change (RAP opcode 115, cleartext NetUserPasswordSet2) is an obsolete LM-only path. The legacy gateway derives only the LM one-way function from the cleartext passwords and calls `SamrChangePasswordUser` with `LmPresent=TRUE, NtPresent=FALSE` and no cross-encryption blobs (verified against the leaked `xactsrv/changepw.c` cleartext branch and `ds/ds/src/sam/server/user.c:8848-8858`), so it can only ever store the new LM hash and never the NT hash. Calling that same LM-only `SamrChangePasswordUser` directly over `\pipe\samr` against an LM-storing account returns `STATUS_SUCCESS` but leaves the NT hash unusable, so NTLM authentication with the new password fails (confirmed live on Server 2003 and NT 4.0). Over the RAP gateway the request instead fails with Win32 `0x3B` (ERROR_UNEXP_NET_ERR, a session-class error from the gateway's impersonated in-process SAM call) before it completes. Either way the path cannot produce an NTLM-usable password; it is meaningful only for pure-LM accounts on a server whose `LmCompatibilityLevel` still permits LM authentication. The working legacy RAP change on SMB1 hosts is `rap-oem` (opcode 214), which carries the new password as an RC4 OEM buffer keyed by the old LM hash. Unlike `rap`, it is not LM-only and does not blank the NT hash: the server decrypts the OEM cleartext and recomputes and stores a real NT OWF (and LM OWF) from it ([MS-SAMR] 3.1.5.10.2; live secretsdump on Server 2003, XP, and Server 2022 shows the post-change NT equals `nt_owf` of the new password, never the empty-password hash). Unlike the cleartext opcode 115 it actually completes on NT 4.0, so it is validated on Windows NT 4.0 and is the legacy change `passwolf change` recommends where LM logon is still honored.

## Change methods

| Method | Protocol / opnum | Spec | Notes |
|---|---|---|---|
| `samr-aes` | SAMR 73 | [MS-SAMR] 3.1.5.10.4 | AES; the only SAMR change Server 2025 accepts; impacket lacks it |
| `samr-rc4` | SAMR 55 | [MS-SAMR] 3.1.5.10.3 | legacy RC4; pass-the-hash capable |
| `samr-oem` | SAMR 54 | [MS-SAMR] 3.1.5.10.2 | OEM/LM RC4; no impacket helper |
| `samr-des` | SAMR 38 | [MS-SAMR] 3.1.5.10.1 | DES OWF cross-encryption; hand-built with the cross-encryption retry, so it is correct for both-stored, NoLMHash, and pass-the-hash changes; needs a handle |
| `samr-diag` | SAMR 63 | leaked samrpc.idl | undocumented; returns the effective password policy and the structured rejection reason; Server 2025 refuses it with ACCESS_DENIED |
| `kpasswd` | Kerberos 464 (0xFF80) | RFC 3244 | change protocol; the wire request carries version 0xFF80 for both change and set, with the change selected by omitting targname/targrealm rather than by the version field (0x0001 is only the server reply version) |
| `ldap` | LDAP unicodePwd | [MS-ADTS] 3.1.1.3.1.5 | delete old + add new; sealed 389 |
| `netlogon-aes` | Netlogon 30 | [MS-NRPC] 3.5.4.4.6 | machine/trust, AES buffer, sealed channel; a trust uses its flat NetBIOS name (`CONTOSO$`) over TrustedDomainSecureChannel |
| `netlogon-des` | Netlogon 6 | [MS-NRPC] 3.5.4.4.7 | machine/trust, DES OWF |
| `rap` | RAP 115 | [MS-RAP] 2.5.8.1 | legacy NetUserPasswordSet2 (cleartext) over SMB1 `\PIPE\LANMAN`; LM-only, see note; Server 2008 and earlier |
| `rap-oem` | RAP 214 | leaked changepw.c | undocumented SamOEMChangePasswordUser2 (RC4 OEM buffer) over SMB1; the working legacy RAP change; Server 2008 and earlier |

## Reset methods

| Method | Protocol / opnum | Spec | Notes |
|---|---|---|---|
| `samr-aes` | SamrSetInformationUser2 (SAMR 58) + UserInternal7 (level 31) | [MS-SAMR] 3.1.5.6.4 | AES cleartext reset, password only; impacket lacks the AES info levels |
| `--reset-info-class internal8` | SamrSetInformationUser2 (SAMR 58) + UserInternal8 (level 32) | [MS-SAMR] 3.1.5.6.4 | AES cleartext reset wrapping UserAllInformation; same cipher, key, and stored result as `samr-aes`, only the wire shape differs |
| `samr-rc4` | SamrSetInformationUser2 (SAMR 58) + UserInternal4New (level 25) | [MS-SAMR] 3.1.5.6.4 | RC4 + MD5-salt cleartext reset (the salted form); the plain UserInternal4/5 (23/24) and the 5New alias (26) exist but passwolf does not emit them |
| `samr-hash` | SamrSetInformationUser (SAMR 37) + UserInternal1 (level 18) | [MS-SAMR] 3.1.5.6.5 | set the NT (and optionally LM) OWF directly, with expiry control (full policy bypass); UserAllInformation (level 21) can also carry the OWF fields. Opnums 37 and 58 are the same server routine ([MS-SAMR] 3.1.5.6.5: 37 "MUST behave as with a call to SamrSetInformationUser2"), so the info class, not the opnum, selects the operation; the opnum split is passwolf convention |
| `kpasswd` | Kerberos 464 (0xFF80) | RFC 3244 | set protocol with target name and realm |
| `ldap` | LDAP unicodePwd | [MS-ADTS] 3.1.1.3.1.5 | single replace; sealed 389 |
| `dsrm` (`--dsrm`) | SamrSetDSRMPassword (SAMR 66) | [MS-SAMR] 3.1.5.13.6 | DC-local recovery (RID 500) password; selected with the dedicated `--dsrm` flag |

## SAMR SetInformationUser info classes (what you can set on a user)

The SAMR reset methods above are all the same two RPC calls, SamrSetInformationUser (opnum 37) and SamrSetInformationUser2 (opnum 58), carrying a different USER_INFORMATION_CLASS. The two opnums are interchangeable: [MS-SAMR] 3.1.5.6.5 states opnum 37 "MUST behave as with a call to SamrSetInformationUser2," and in the leaked source the body of opnum 58 is literally `return SamrSetInformationUser(...)`. The routines dispatch only on the info class, never on the opnum, so every class below can ride either opnum; passwolf's choice of 37 for the hash level and 58 for the cleartext and AES levels is a code convention, not a wire requirement. This was confirmed live: every class returns the same status under both opnums on Server 2022 and Server 2025.

### Account-attribute classes (no password)

These set ordinary account fields and carry no credential material. They need USER_WRITE_ACCOUNT (or USER_WRITE_PREFERENCES for the preferences class) and work over either transport.

| Info class (value) | What it sets | Access right |
|---|---|---|
| UserPreferencesInformation (2) | UserComment, CountryCode, CodePage | USER_WRITE_PREFERENCES |
| UserLogonHoursInformation (4) | Logon-hours bitmap | USER_WRITE_ACCOUNT |
| UserNameInformation (6) | Account name plus full name | USER_WRITE_ACCOUNT |
| UserAccountNameInformation (7) | sAMAccountName | USER_WRITE_ACCOUNT |
| UserFullNameInformation (8) | displayName | USER_WRITE_ACCOUNT |
| UserPrimaryGroupInformation (9) | primaryGroupID | USER_WRITE_ACCOUNT |
| UserHomeInformation (10) | Home directory and drive | USER_WRITE_ACCOUNT |
| UserScriptInformation (11) | Logon script path | USER_WRITE_ACCOUNT |
| UserProfileInformation (12) | Profile path | USER_WRITE_ACCOUNT |
| UserAdminCommentInformation (13) | description (admin comment) | USER_WRITE_ACCOUNT |
| UserWorkStationsInformation (14) | Logon workstations list | USER_WRITE_ACCOUNT |
| UserControlInformation (16) | userAccountControl flags (enable, disable, and so on) | USER_WRITE_ACCOUNT |
| UserExpiresInformation (17) | accountExpires | USER_WRITE_ACCOUNT |
| UserParametersInformation (20) | userParameters | USER_WRITE_ACCOUNT |

### Password classes

These carry credential material and need USER_FORCE_PASSWORD_CHANGE. The wire protection always keys on the 16-byte SMB session key, which is why every password class is RPC-over-SMB-named-pipe only (no TCP).

| Info class (value) | What it sets | Wire protection of the password |
|---|---|---|
| UserInternal1Information (18) | Raw NT and optionally LM OWF (set a hash from a hash); bypasses length, complexity, history, minimum age | Each 16-byte OWF half DES-encrypted with the SMB session key ([MS-SAMR] 2.2.11.1.1) |
| UserInternal4Information (23) | Cleartext password, wraps an all-information block | SAMPR_ENCRYPTED_USER_PASSWORD (516 bytes), RC4 keyed by the session key ([MS-SAMR] 3.2.2.1) |
| UserInternal5Information (24) | Cleartext password, plus a PasswordExpired flag | SAMPR_ENCRYPTED_USER_PASSWORD (516 bytes), RC4 keyed by the session key; server maps it to UserInternal4 |
| UserInternal4InformationNew (25) | Cleartext password, wraps an all-information block | SAMPR_ENCRYPTED_USER_PASSWORD_NEW (532 bytes), RC4 keyed by MD5(16-byte clear salt + session key) ([MS-SAMR] 3.2.2.2) |
| UserInternal5InformationNew (26) | Cleartext password, plus a PasswordExpired flag | SAMPR_ENCRYPTED_USER_PASSWORD_NEW (532 bytes), salted RC4; server maps it to UserInternal4New |
| UserInternal7Information (31) | Cleartext password, plus a PasswordExpired flag (modern strongest) | SAMPR_ENCRYPTED_PASSWORD_AES, AEAD-AES-256-CBC-HMAC-SHA512 ([MS-SAMR] 3.2.2.4), key is the session key; server maps it to UserInternal8 |
| UserInternal8Information (32) | Cleartext password, wraps a full all-information block | SAMPR_ENCRYPTED_PASSWORD_AES, AEAD-AES-256-CBC-HMAC-SHA512, key is the session key |
| UserSetPasswordInformation (15) | Cleartext password, plaintext on the wire | None (no buffer cipher). Legacy and local only; remote clients map it to UserInternal1, and the server-side set arm is a dead assert. Absent from the modern [MS-SAMR] enum |
| UserAllInformation (21) | Any combination of the account-attribute fields above, and the raw NT and optionally LM OWF | Account fields plain. The NT and LM OWF fields use the same DES-over-session-key protection as UserInternal1 |

Two classes set a raw hash directly: UserInternal1 (the dedicated hash class passwolf uses) and UserAllInformation (which can also carry the NT and LM OWF fields). Both are settable by a remote, non-trusted caller holding USER_FORCE_PASSWORD_CHANGE, and both were confirmed live to set the NT hash and let the new password log in on Server 2022 and Server 2025 over opnum 37 and opnum 58. On NoLMHash domains (the modern default) the LM half is not stored, but the NT half authenticates. The OWF fields sit in USER_ALL_WRITE_FORCE_PASSWORD_CHANGE_MASK, not the trusted-only mask, so this is a force-password-change right, not a trusted-caller requirement.

### Not settable by a remote client

| Info class (value) | Reason |
|---|---|
| UserGeneralInformation (1), UserLogonInformation (3), UserAccountInformation (5) | Query only. No set arm; the set switch default returns STATUS_INVALID_INFO_CLASS |
| UserInternal2Information (19) | Logon statistics (BadPasswordCount, LogonCount, LastLogon, LastLogoff). Settable only by an in-process trusted caller; the remote branch returns STATUS_INVALID_INFO_CLASS. Absent from the modern enum |
| UserInternal3Information (22) | A query-result layout (all-information plus LastBadPasswordTime); no settable behavior. Returns STATUS_INVALID_INFO_CLASS. Absent from the modern enum |
| UserInternal6Information (27) | Query only; not present in the set union. Returns STATUS_INVALID_INFO_CLASS. Absent from the modern enum |

There is no UserInternal9 or UserInternal10, and the only salted variants are 4New and 5New. The modern [MS-SAMR] enum (v20260427) omits 15, 19, 22, and 27 entirely, jumping 18, 20, 21, 23, 24, 25, 26, 31, 32.

### The UserInternal family side by side

| Level (value) | Hash or cleartext | Cipher and key | Buffer | passwolf method |
|---|---|---|---|---|
| UserInternal1 (18) | Hash (raw NT, optional LM OWF) | DES-ECB over each 16-byte OWF half, keyed by the session key | SAMPR_USER_INTERNAL1_INFORMATION | `samr-hash` (opnum 37). The only dedicated hash class. Does not regenerate Kerberos AES keys |
| UserInternal4 (23) | Cleartext, wraps all-info | RC4 over 516 bytes, keyed by the session key | SAMPR_ENCRYPTED_USER_PASSWORD | Server accepts it; passwolf does not emit it (unsalted) |
| UserInternal5 (24) | Cleartext, no all-info | RC4 over 516 bytes, keyed by the session key | SAMPR_ENCRYPTED_USER_PASSWORD | Maps to UserInternal4; passwolf does not emit it |
| UserInternal4New (25) | Cleartext, wraps all-info | RC4 over 516 bytes, keyed by MD5(salt + session key) | SAMPR_ENCRYPTED_USER_PASSWORD_NEW (532) | `samr-rc4` (opnum 58). The salted RC4 reset; `auto` reaches it after AES in its ladder |
| UserInternal5New (26) | Cleartext, no all-info | Salted RC4, same derivation as 25 | SAMPR_ENCRYPTED_USER_PASSWORD_NEW (532) | Maps to UserInternal4New; passwolf does not emit it |
| UserInternal7 (31) | Cleartext, no all-info | AEAD-AES-256, key is the session key | SAMPR_ENCRYPTED_PASSWORD_AES | `samr-aes` (opnum 58). Password-only AES; strongest cleartext path |
| UserInternal8 (32) | Cleartext, wraps all-info | AEAD-AES-256, key is the session key | SAMPR_ENCRYPTED_PASSWORD_AES plus all-info | `--reset-info-class internal8` (opnum 58). Same cipher, key, and stored result as UserInternal7; only the wire shape differs |

Read off the table: level 18 is the only dedicated hash path, 23 and 24 are plain RC4, 25 and 26 are salted RC4, 31 and 32 are AES, and all key on the 16-byte SMB session key. The "wraps all-info" versus "no all-info" split is only a wire-shape difference; the server collapses the wrapped and unwrapped forms to one processing path (5 to 4, 5New to 4New, 7 to 8), so the stored credential is identical. passwolf emits only four: 18 (`samr-hash`), 25 (`samr-rc4`), 31 (`samr-aes`), 32 (`--reset-info-class internal8`).

## Read methods

`passwolf policy` reads the policy without mutating anything. The opnum-63 and kpasswd entries are oracles: they submit a guaranteed policy-violating new password so the server returns the effective policy in its rejection, and the probed account is never changed.

| Method | Protocol / opnum | Spec | Notes |
|---|---|---|---|
| `samr-query` | SAMR 46 (8 fallback) | [MS-SAMR] 3.1.5.5.1 | default policy from classes 1 (password), 12 (lockout), 3 (force-logoff); denied to anonymous on modern DCs |
| `samr-getdompwinfo` | SAMR 56 | [MS-SAMR] 3.1.5.13.2 | handle-light length + properties; spec calls it handle-less/anonymous but in practice anonymous is denied on every host tested (legacy and modern), readable by any authenticated principal |
| `samr-getusrpwinfo` | SAMR 44 | [MS-SAMR] 3.1.5.13.1 | per-user length + properties, PSO-effective |
| `samr-diag` | SAMR 63 | leaked samrpc.idl | opnum-63 oracle, PSO-effective full policy + failure reason; Server 2025 refuses it with ACCESS_DENIED |
| `kpasswd` | Kerberos 464 SOFTERROR | RFC 3244 | SOFTERROR oracle, PSO-effective for the authenticating principal; not RC4-gated, so it works on Server 2025 |
| `ldap-domain-head` | LDAP domainDNS attrs | [MS-ADTS] 3.1.1.4 | most complete single default-policy read; needs an authenticated bind |
| `ldap-pso` | LDAP PSC msDS-PasswordSettings | [MS-ADTS] 6.1.1.4.11.1 | every PSO; complexity/reversible as explicit booleans; values gated by the container ACL (name-only for non-admins) |
| `ldap-resultant` | LDAP msDS-ResultantPSO | [MS-ADTS] 3.1.1.4.5.36 | the winning PSO DN for the subject, dereferenced |
| `ldap-uac` | LDAP msDS-User-Account-Control-Computed | [MS-ADTS] 3.1.1.4.5.17 | subject lockout/expiry state and bad-password count |
| `sysvol` | SMB SYSVOL GptTmpl.inf | [MS-GPSB] 2.2.1 | configured intent per GPO, a cross-check against the live values |

PSO-awareness is the key distinction among the read methods. Opnum 44, opnum 63, kpasswd, and the resultant-PSO read all resolve the subject's effective policy, so a fine-grained password policy bound to the subject is reflected; the default methods (`samr-query`, `samr-getdompwinfo`, `ldap-domain-head`, `sysvol`) always report the domain-wide policy. The kpasswd oracle reports the policy of the authenticating principal, so reading a specific subject's PSO-effective policy through kpasswd means authenticating as that subject. In this lab no PSO was bound to the test account, so all read methods returned the domain default minimum length of 7 (the opnum-63 effective-policy out-param was observed returning MinPasswordLength=7). The PSO-effective behavior is asserted from the spec, not exercised live.
