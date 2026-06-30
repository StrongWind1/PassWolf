# SAMR RPC reference

This is the per-interface RPC reference for **SAMR**, the Security Account Manager Remote Protocol ([MS-SAMR]). It is the first interface in the reference; Netlogon ([MS-NRPC]) and the kpasswd/LDAP paths get their own pages later. Everything below is cross-checked against three sources that agree on the wire format but disagree on coverage: the published spec (`MS-SAMR`, v20260427), the impacket NDR definitions (`impacket/dcerpc/v5/samr.py`), and the leaked Windows Server 2003 SAM source (`ds/ds/src/sam/`), plus an empty-stub opnum probe run against a live Server 2022 DC (build 20348) and a live Server 2025 DC (build 26100). Where the three sources diverge, the divergence is called out explicitly; that is the useful part.

## What SAMR is

SAMR is the Microsoft RPC interface to the **Security Account Manager**: the account database a domain controller exposes for reading and writing users, groups, aliases, and domain objects. It is the protocol behind `net user`, behind most account-management GUIs, and behind the password operations this tool performs. For passwords specifically, SAMR carries three distinct jobs:

- **Change**: prove the current password and set a new one (any user, own account). Opnums 38, 54, 55, 63, 73.
- **Reset**: set a new password *without* the old one, using the force-change-password right (privileged). Opnums 37, 58, 66.
- **Policy collection**: read the password policy the DC will enforce, so a change/reset can be validated up front. Opnums 8, 44, 46, 56, 67.

The interface UUID is `12345778-1234-ABCD-EF00-0123456789AC`, version `1.0`. Every method has a fixed opnum; the wire is NDR-encoded DCE/RPC.

## How to access it

SAMR is an MSRPC interface, so a call always rides on a lower transport. Two are relevant:

| Transport | Binding string | What carries it | Notes |
|---|---|---|---|
| RPC over SMB named pipe | `ncacn_np:<dc>[\pipe\samr]` | SMB on TCP 445 | The default. Gives you an **SMB session key**, which the reset and RC4-change buffers need. |
| RPC over TCP | `ncacn_ip_tcp:<dc>` | a dynamic TCP port found via the endpoint mapper (TCP 135) | No SMB, no pipe, no session key. Used to reach methods that are gated off the pipe (e.g. opnum 67). |

"The pipe", "over SMB", and "RPC over SMB" all name the same `ncacn_np` path; they are not three transports. The split that actually matters for passwords:

- **Changes** key their password buffer on something the *caller already knows* (the old password, or a hash derived from it), so they work over **either** transport, including against a null session.
- **Resets** key their password buffer on the **SMB session key**, which only exists over `ncacn_np`, so every SAMR reset is **pipe-only**.

Authentication to the bind can be NTLM (password or pass-the-hash), Kerberos (`RPC_C_AUTHN_GSS_NEGOTIATE`, with `KRB5CCNAME` honored), or a **null session** (anonymous). The buffer-based change methods (54/55/63/73) carry their own proof-of-old-password and are explicitly callable over a null session per [MS-SAMR] 3.1.5.10.3; passwolf uses exactly that to retry an expired-password change after the authenticated bind is rejected.

## Master table: all 80 opnums (0–79)

The SAMR interface defines opnums **0 through 79**, 80 methods, no more. Every slot is named here, including the ones the public spec marks `OpnumNNNotUsedOnWire`: those names come from the proc table of a live Windows 11 `samsrv.dll` (build 26200.7840, extracted with NtObjectManager), so a slot the spec calls "reserved for local use" still has a real server method name. Names tagged **†** are present in the DLL but documented by the spec as NotUsedOnWire (reserved for local/in-process callers, not remote clients). There is no opnum 80 or 81; the interface ends at 79.

"Calls (impacket)" is the high-level `hSamr*` helper impacket ships for that opnum (`none` = no helper; the method must be hand-built or is not in impacket at all). The three "useful for" columns mark password relevance. "Live over NP" folds the empty-stub probe against the lab DCs (Server 2022 build 20348, Server 2025 build 26100): **present** = reachable over the named pipe (returned `RPC_X_BAD_STUB_DATA` to an empty stub), **gated** = present but `rpc_s_access_denied` over NP (try TCP / higher privilege), **n/r** = not reachable over NP on those builds.

| Opnum | Method | Calls (impacket) | Change | Reset | Policy | Purpose | Live over NP |
|---|---|---|:--:|:--:|:--:|---|---|
| 0 | SamrConnect | `hSamrConnect` | | | | Handle to the server object | present |
| 1 | SamrCloseHandle | `hSamrCloseHandle` | | | | Close any context handle | present |
| 2 | SamrSetSecurityObject | `hSamrSetSecurityObject` | | | | Set ACL on an object | present |
| 3 | SamrQuerySecurityObject | `hSamrQuerySecurityObject` | | | | Read ACL on an object | present |
| 4 | SamrShutdownSamServer † | none | | | | Shut down the SAM server (local/admin) | n/r |
| 5 | SamrLookupDomainInSamServer | `hSamrLookupDomainInSamServer` | | | | Domain name → domain SID | present |
| 6 | SamrEnumerateDomainsInSamServer | `hSamrEnumerateDomainsInSamServer` | | | | List hosted domains | present |
| 7 | SamrOpenDomain | `hSamrOpenDomain` | ✓ | ✓ | ✓ | Handle to a domain object (prereq for all three jobs) | present |
| 8 | **SamrQueryInformationDomain** | `hSamrQueryInformationDomain` | | | ✓ | Read domain attributes incl. password policy | present |
| 9 | SamrSetInformationDomain | `hSamrSetInformationDomain` | | | | Write domain attributes | present |
| 10 | SamrCreateGroupInDomain | `hSamrCreateGroupInDomain` | | | | Create a group | present |
| 11 | SamrEnumerateGroupsInDomain | `hSamrEnumerateGroupsInDomain` | | | | List groups | present |
| 12 | SamrCreateUserInDomain | `hSamrCreateUserInDomain` | | | | Create a user | present |
| 13 | SamrEnumerateUsersInDomain | `hSamrEnumerateUsersInDomain` | | | | List users | present |
| 14 | SamrCreateAliasInDomain | `hSamrCreateAliasInDomain` | | | | Create an alias | present |
| 15 | SamrEnumerateAliasesInDomain | `hSamrEnumerateAliasesInDomain` | | | | List aliases | present |
| 16 | SamrGetAliasMembership | `hSamrGetAliasMembership` | | | | Aliases a SID set belongs to | present |
| 17 | SamrLookupNamesInDomain | `hSamrLookupNamesInDomain` | ✓ | ✓ | ✓ | Account names → RIDs (prereq for opening a user) | present |
| 18 | SamrLookupIdsInDomain | `hSamrLookupIdsInDomain` | | | | RIDs → account names | present |
| 19 | SamrOpenGroup | `hSamrOpenGroup` | | | | Handle to a group | present |
| 20 | SamrQueryInformationGroup | `hSamrQueryInformationGroup` | | | | Read group attributes | present |
| 21 | SamrSetInformationGroup | `hSamrSetInformationGroup` | | | | Write group attributes | present |
| 22 | SamrAddMemberToGroup | `hSamrAddMemberToGroup` | | | | Add a group member | present |
| 23 | SamrDeleteGroup | `hSamrDeleteGroup` | | | | Delete a group | present |
| 24 | SamrRemoveMemberFromGroup | `hSamrRemoveMemberFromGroup` | | | | Remove a group member | present |
| 25 | SamrGetMembersInGroup | `hSamrGetMembersInGroup` | | | | Read group members | present |
| 26 | SamrSetMemberAttributesOfGroup | `hSamrSetMemberAttributesOfGroup` | | | | Set member attributes | present |
| 27 | SamrOpenAlias | `hSamrOpenAlias` | | | | Handle to an alias | present |
| 28 | SamrQueryInformationAlias | `hSamrQueryInformationAlias` | | | | Read alias attributes | present |
| 29 | SamrSetInformationAlias | `hSamrSetInformationAlias` | | | | Write alias attributes | present |
| 30 | SamrDeleteAlias | `hSamrDeleteAlias` | | | | Delete an alias | present |
| 31 | SamrAddMemberToAlias | `hSamrAddMemberToAlias` | | | | Add an alias member | present |
| 32 | SamrRemoveMemberFromAlias | `hSamrRemoveMemberFromAlias` | | | | Remove an alias member | present |
| 33 | SamrGetMembersInAlias | `hSamrGetMembersInAlias` | | | | Read alias members | present |
| 34 | SamrOpenUser | `hSamrOpenUser` | ✓ | ✓ | ✓ | Handle to a user object (prereq for DES change, every reset, per-user policy) | present |
| 35 | SamrDeleteUser | `hSamrDeleteUser` | | | | Delete a user | present |
| 36 | SamrQueryInformationUser | `hSamrQueryInformationUser` | | | ✓ | Read user attributes | present |
| 37 | **SamrSetInformationUser** | `hSamrSetInformationUser` | | ✓ | | Write user attributes; reset path (info-class picks cipher) | present |
| 38 | **SamrChangePasswordUser** | `hSamrChangePasswordUser` | ✓ | | | DES cross-encryption change (needs a user handle) | present |
| 39 | SamrGetGroupsForUser | `hSamrGetGroupsForUser` | | | | Groups a user belongs to | present |
| 40 | SamrQueryDisplayInformation | `hSamrQueryDisplayInformation` | | | | Name-sorted account list | present |
| 41 | SamrGetDisplayEnumerationIndex | `hSamrGetDisplayEnumerationIndex` | | | | Index into the sorted list | present |
| 42 | SamrTestPrivateFunctionsDomain † | none | | | | Test stub (checked builds only) | present¹ |
| 43 | SamrTestPrivateFunctionsUser † | none | | | | Test stub (checked builds only) | present¹ |
| 44 | **SamrGetUserDomainPasswordInformation** | `hSamrGetUserDomainPasswordInformation` | | | ✓ | Per-user min-length + properties (PSO-resolved) | present |
| 45 | SamrRemoveMemberFromForeignDomain | `hSamrRemoveMemberFromForeignDomain` | | | | Remove a member from all aliases | present |
| 46 | **SamrQueryInformationDomain2** | `hSamrQueryInformationDomain2` | | | ✓ | Read domain attributes incl. password policy (preferred over opnum 8) | present |
| 47 | SamrQueryInformationUser2 | `hSamrQueryInformationUser2` | | | ✓ | Read user attributes (v2) | present |
| 48 | SamrQueryDisplayInformation2 | `hSamrQueryDisplayInformation2` | | | | Name-sorted account list (v2) | present |
| 49 | SamrGetDisplayEnumerationIndex2 | `hSamrGetDisplayEnumerationIndex2` | | | | Index into the sorted list (v2) | present |
| 50 | SamrCreateUser2InDomain | `hSamrCreateUser2InDomain` | | | | Create a user (v2) | present |
| 51 | SamrQueryDisplayInformation3 | `hSamrQueryDisplayInformation3` | | | | Name-sorted account list (v3) | present |
| 52 | SamrAddMultipleMembersToAlias | `hSamrAddMultipleMembersToAlias` | | | | Add multiple alias members | present |
| 53 | SamrRemoveMultipleMembersFromAlias | `hSamrRemoveMultipleMembersFromAlias` | | | | Remove multiple alias members | present |
| 54 | **SamrOemChangePasswordUser2** | none | ✓ | | | LM/OEM change, RC4 keyed by old LM hash | present |
| 55 | **SamrUnicodeChangePasswordUser2** | `hSamrUnicodeChangePasswordUser2` | ✓ | | | RC4 change keyed by old NT hash | present |
| 56 | **SamrGetDomainPasswordInformation** | `hSamrGetDomainPasswordInformation` | | | ✓ | Handle-light min-length + properties | present |
| 57 | SamrConnect2 | `hSamrConnect2` | | | | Handle to the server object (v2) | present |
| 58 | **SamrSetInformationUser2** | `hSamrSetInformationUser2` | | ✓ | | Write user attributes; the main reset opnum (info-class picks cipher) | present |
| 59 | SamrSetBootKeyInformation † | none | | | | Set the SYSKEY / boot key (local) | gated |
| 60 | SamrGetBootKeyInformation † | none | | | | Get the SYSKEY / boot key (local) | present¹ |
| 61 | SamrConnect3 † | none | | | | Obsolete connect variant | present¹ |
| 62 | SamrConnect4 | `hSamrConnect4` | | | | Handle to the server object (v4) | present |
| 63 | **SamrUnicodeChangePasswordUser3** † | none | ✓ | | ✓ | Undocumented RC4 change that **returns the effective policy and the failure reason** | present |
| 64 | SamrConnect5 | `hSamrConnect5` | | | | Handle to the server object (v5) | present |
| 65 | SamrRidToSid | `hSamrRidToSid` | | | | RID → full SID | present |
| 66 | **SamrSetDSRMPassword** | none | | ✓ | | Set the DC-local recovery (DSRM) account password | present |
| 67 | **SamrValidatePassword** | `hSamrValidatePassword` | | | ✓ | Validate a password against stored policy | gated² |
| 68 | SamrQueryLocalizableAccountsInDomain † | none | | | | Query localizable built-in accounts | n/r |
| 69 | SamrPerformGenericOperation † | none | | | | Generic operation dispatch | n/r |
| 70 | SamrSyncDSRMPasswordFromAccount † | none | | | | Sync the DSRM password from a domain account | n/r |
| 71 | SamrLookupNamesInDomain2 † | none | | | | Names → RIDs (v2) | n/r |
| 72 | SamrEnumerateUsersInDomain2 † | none | | | | Enumerate users (v2) | n/r |
| 73 | **SamrUnicodeChangePasswordUser4** | none | ✓ | | | AES change; key derived from old password via PBKDF2 | present |
| 74 | SamrValidateComputerAccountReuseAttempt | none | | | | Validate computer-account reuse | present |
| 75 | SamrQueryLapsManagedAccount † | none | | | | Read a LAPS-managed local account password | n/r |
| 76 | SamrLapsSysprepCleanup † | none | | | | LAPS sysprep cleanup | n/r |
| 77 | SamrAccountIsDelegatedManagedServiceAccount | none | | | | Is the account a delegated MSA | present on 2025; gated on 2022³ |
| 78 | SamrFindOrCreateShadowAdminAccount † | none | | | | Find/create the shadow-admin recovery account | n/r |
| 79 | SamrIsShadowAdminAccount † | none | | | | Is the account a shadow-admin account | n/r |

✓ = useful for this job, either directly or as a required prerequisite (open a handle, look up a RID, read attributes). A **bold method name** is one that *directly performs* a change, reset, or policy-collection (the methods detailed in the per-purpose tables below); unbold rows with a ✓ are prerequisite or read-only support steps. **†** = present in the live `samsrv.dll` proc table but documented `OpnumNNNotUsedOnWire` by the spec (reserved for local/in-process callers).

¹ Probe returned present (bad-stub) even though the spec marks the opnum NotUsedOnWire; the dispatch slot is wired up on the live build but the method is reserved for local (in-process) callers. Do not treat "present" as "callable for our purposes".
² `SamrValidatePassword` is rejected over `ncacn_np` on Vista SP2 and later (note `<8>` in [MS-SAMR] 3.1.5.13.7); reach it over `ncacn_ip_tcp`.
³ Build delta: opnum 77 is present on Server 2025 (build 26100) but `access_denied` on Server 2022 (build 20348). Opnums 68–72, 75, 76, 78, 79 are named in the build-26200 DLL but returned `access_denied` (n/r) on the probed 20348/26100 DCs; they are newer or local-only and were not remotely callable there.

## Methods useful for changing a password

A change proves possession of the old password inside the request, so no force-change right is needed and the call works over a null session. Five opnums; passwolf wires each to one `ChangeMethod`.

| Opnum / method | passwolf method | Input password structure | Other inputs | Outputs | Cipher / key |
|---|---|---|---|---|---|
| 73 `SamrUnicodeChangePasswordUser4` | `SAMR_AES` (`change_aes`) | `SAMPR_ENCRYPTED_PASSWORD_AES` (wraps `SAMPR_USER_PASSWORD_AES`) | server name, account name, PBKDF2 iteration count | NTSTATUS only (no handle) | AES-256 AEAD; key = PBKDF2(old-password NT hash, Salt, iterations) |
| 55 `SamrUnicodeChangePasswordUser2` | `SAMR_RC4` (`change_rc4`) | `SAMPR_ENCRYPTED_USER_PASSWORD` (wraps `SAMPR_USER_PASSWORD`) | account name, `OldNtOwfPasswordEncryptedWithNewNt` verifier (`ENCRYPTED_LM_OWF_PASSWORD`) | NTSTATUS only | RC4 keyed by old NT hash; verifier proves the old hash |
| 54 `SamrOemChangePasswordUser2` | `SAMR_OEM` (`change_oem`) | `SAMPR_ENCRYPTED_USER_PASSWORD` (OEM/ANSI cleartext) | account name (OEM string), `OldLmOwfPasswordEncryptedWithNewLm` verifier | NTSTATUS only | RC4 keyed by old **LM** hash; only works if an LM hash is stored |
| 63 `SamrUnicodeChangePasswordUser3` *(undocumented)* | `SAMR_DIAG` (`change_diag`) | `SAMPR_ENCRYPTED_USER_PASSWORD` (as User2) | account name, `OldNtOwfPasswordEncryptedWithNewNt` verifier, `AdditionalData` buffer | NTSTATUS **plus** `EffectivePasswordPolicy` (`PDOMAIN_PASSWORD_INFORMATION`) **plus** `PasswordChangeInfo` (`PUSER_PWD_CHANGE_FAILURE_INFORMATION`) | RC4 (as User2); the extra outputs say *why* a change was rejected |
| 38 `SamrChangePasswordUser` | `SAMR_DES` (`change_des`) | `ENCRYPTED_NT_OWF_PASSWORD` + `ENCRYPTED_LM_OWF_PASSWORD` pairs (no cleartext buffer) | **user handle** (from `SamrOpenUser`), the four cross-encryption blobs, present/cross flags | NTSTATUS only | DES OWF cross-encryption: old and new hashes encrypt each other ([MS-SAMR] 3.1.5.10.1) |

Notes that matter on a modern DC:

- Only opnum 73 (AES) survives Server 2025's RC4 hardening (CVE-2021-33757 / KB5004605). Opnums 55, 54, 38 are blocked there.
- Opnum 38 is the only change that needs an open **user handle**, so it is the only change that **cannot** run over a null session. The other four carry the old-secret proof in the request body and bind anonymously.
- Opnum 38 can set the new password **by hash**: pass new NT/LM OWF values directly instead of a cleartext password. passwolf's `change_des` with `new_nt_hash` set sends an NT-only request with the LM-cross flag set, matching impacket's `hSamrChangePasswordUser`.
- Opnum 63 is **undocumented** (spec says "Opnum63NotUsedOnWire, reserved for local use") but is live and reachable on both 2022 and 2025. Its value is the two extra out-parameters: the effective policy and a structured failure reason. passwolf uses it as a diagnostic oracle.

## Methods useful for resetting a password

A reset writes the new password with no proof of the old one, so it needs the force-change-password right and a privileged bind. Every domain-user reset rides opnum 37 or 58, and the two are interchangeable: [MS-SAMR] 3.1.5.6.5 says opnum 37 "MUST behave as with a call to SamrSetInformationUser2," and in the leaked source the body of opnum 58 is literally `return SamrSetInformationUser(...)`. **What varies is the info class inside the request, not the opnum**: the info class picks the cipher and what gets written.

| Opnum / method | passwolf method | Info class (USERINFO) | Input password structure | Other inputs | Outputs | Cipher / key |
|---|---|---|---|---|---|---|
| 58 `SamrSetInformationUser2` | `SAMR_AES` (`reset_aes`) | `UserInternal7Information` (31) | `SAMPR_USER_INTERNAL7_INFORMATION` → `SAMPR_ENCRYPTED_PASSWORD_AES` | user handle, expire flag | NTSTATUS | AES-256 AEAD; key = SMB session key |
| 58 `SamrSetInformationUser2` | `--reset-info-class internal8` (`_build_internal8` via `reset_set_information`) | `UserInternal8Information` (32) | `SAMPR_USER_INTERNAL8_INFORMATION` → `SAMPR_ENCRYPTED_PASSWORD_AES` inside `SAMPR_USER_ALL_INFORMATION` | user handle, expire flag | NTSTATUS | AES-256 AEAD; key = SMB session key (same cipher as Internal7, different wire shape) |
| 58 `SamrSetInformationUser2` | `SAMR_RC4` (`reset_rc4`) | `UserInternal4InformationNew` (25) | `SAMPR_USER_INTERNAL4_INFORMATION_NEW` → `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` | user handle, expire flag | NTSTATUS | RC4 + MD5 salt; key = SMB session key |
| 37 `SamrSetInformationUser` | `SAMR_HASH` (`reset_hash`) | `UserInternal1Information` (18) | `SAMPR_USER_INTERNAL1_INFORMATION` (NT/LM OWF, no cleartext) | user handle, NT hash, optional LM hash, present flags, expire flag | NTSTATUS | DES; NT/LM OWF encrypted with the SMB session key; **policy bypass** (no length/complexity/history/min-age check) |
| 66 `SamrSetDSRMPassword` | `DSRM` (`reset_dsrm`) | none (dedicated method, not an info class) | `EncryptedNtOwfPassword` (raw NT OWF, no info class) | RID 500 forced server-side; no object handle (raw RPC binding) | NTSTATUS | DES; NT OWF keyed by the account RID. Sets the **DC-local** recovery account, not a domain user |

Notes:

- All SAMR resets are **pipe-only** because they encrypt the password buffer with the **SMB session key**, which only exists over `ncacn_np`. None are blocked on Server 2025: the RC4 hardening targets changes, not resets.
- The first three rows go through the same opnum (58). passwolf chooses the info class, not the opnum, when you pick `--method samr-aes` / `--method samr-rc4` or `--reset-info-class internal8`.
- `SAMR_HASH` (UserInternal1) is the set-by-hash reset: it writes the raw NT (and optional LM) OWF and skips every policy check. `UserAllInformation` (21) can carry the same OWF fields and also works remotely, but passwolf uses the dedicated UserInternal1 class.

### Why opnum 37 for the hash reset and 58 for the rest

Opnums 37 and 58 are **functionally identical**: [MS-SAMR] 3.1.5.6.5 says `SamrSetInformationUser` (37) "MUST behave as with a call to `SamrSetInformationUser2`" with identical arguments and message processing; opnum 37 just re-dispatches into opnum 58's logic on the server. So `UserInternal1` (the hash set) would work the same over either. passwolf sends it over **37** to mirror the native Windows client and impacket, not because 58 can't carry it:

- The spec's client-behavior note (§3.1.5.6.4 method table) has Windows clients call **37 for every info level except** `UserInternal4InformationNew` and `UserInternal5InformationNew`, and **58 only for those**. `UserInternal1` is a "37 level" on a real client.
- impacket matches this: `hSamrSetNTInternal1` → opnum 37; `hSamrSetPasswordInternal4New` → opnum 58.
- Opnum 58 is the "current" method and 37 the deprecated fallback (§1.7.2), so the modern-only structures (salted RC4 (`UserInternal4New`) and AES (`UserInternal7/8`)) must ride 58.

Net split, matching Windows: classic levels (incl. the `UserInternal1` hash) → **37**; salted-RC4 and AES levels → **58**.

### USER_INFORMATION_CLASS accepted by SamrSetInformationUser2 (opnum 58)

Per the processing rules in [MS-SAMR] 3.1.5.6.4 and Common Processing 3.1.5.6.4.1, the server accepts **22 settable classes**; anything else returns an error. Several are *re-mapped* server-side to a canonical class before processing (column "Server maps to"). The same set is valid on opnum 37 except the two `*New` salted levels, which are 58-only on a real client.

| Value | USER_INFORMATION_CLASS | Server maps to | Password-bearing? | passwolf reset |
|---|---|---|:--:|---|
| 2 | UserPreferencesInformation | UserAllInformation | no | none |
| 4 | UserLogonHoursInformation | UserAllInformation | no | none |
| 6 | UserNameInformation | UserAllInformation | no | none |
| 7 | UserAccountNameInformation | UserAllInformation | no | none |
| 8 | UserFullNameInformation | UserAllInformation | no | none |
| 9 | UserPrimaryGroupInformation | UserAllInformation | no | none |
| 10 | UserHomeInformation | UserAllInformation | no | none |
| 11 | UserScriptInformation | UserAllInformation | no | none |
| 12 | UserProfileInformation | UserAllInformation | no | none |
| 13 | UserAdminCommentInformation | UserAllInformation | no | none |
| 14 | UserWorkStationsInformation | UserAllInformation | no | none |
| 16 | UserControlInformation | UserAllInformation | no | none |
| 17 | UserExpiresInformation | UserAllInformation | no | none |
| 18 | **UserInternal1Information** | UserAllInformation (NT/LM OWF fields) | **NT/LM hash** | `SAMR_HASH` (opnum **37**) / `--reset-info-class internal1` |
| 20 | UserParametersInformation | UserAllInformation | no | none |
| 21 | **UserAllInformation** | (native; own section 3.1.5.6.4.3) | **NT/LM hash** (if OWF WhichFields set) | `--reset-info-class userall` |
| 23 | **UserInternal4Information** | (native; own section 3.1.5.6.4.4) | **cleartext (RC4)** | `samr-rc4-unsalted` / `--reset-info-class internal4` |
| 24 | UserInternal5Information | UserInternal4Information | **cleartext (RC4)** | `--reset-info-class internal5` |
| 25 | **UserInternal4InformationNew** | (native; own section 3.1.5.6.4.5) | **cleartext (RC4 + salt)** | `SAMR_RC4` / `--reset-info-class internal4new` |
| 26 | UserInternal5InformationNew | UserInternal4InformationNew | **cleartext (RC4 + salt)** | `--reset-info-class internal5new` |
| 31 | **UserInternal7Information** | UserInternal8Information | **cleartext (AES)** | `SAMR_AES` / `--reset-info-class internal7` |
| 32 | **UserInternal8Information** | (native; own section 3.1.5.6.4.6) | **cleartext (AES)** | `--reset-info-class internal8` |

Rejected by Set (query-only; `SamrSetInformationUser2` returns an error): `UserGeneralInformation` (1), `UserLogonInformation` (3), `UserAccountInformation` (5).

All eight password-bearing classes are reachable from `passwolf reset`: four through the standard `--method` shortcuts (`samr-hash`, `samr-rc4`, `samr-rc4-unsalted`, `samr-aes`) and all eight through the advanced `--reset-info-class` flag, over either opnum via `--reset-opnum {37,58}`.

Note the consequence of the re-mapping: a client can send `UserInternal7` (31, AES password-only) and the server processes it **exactly as** `UserInternal8` (32, AES in an all-info block): same cipher, same key, same stored result. Likewise `UserInternal5/5New` collapse onto `UserInternal4/4New`. So of the password-bearing classes, only four are truly distinct on the wire: hash (`UserInternal1`/`UserAll`), unsalted RC4 (`UserInternal4`), salted RC4 (`UserInternal4New`), and AES (`UserInternal8`).

## Methods useful for collecting the password policy

Policy reads let a change/reset validate the new password before sending it, and let `passwolf policy` report the effective rules. SAMR exposes four reads plus one validator.

| Opnum / method | passwolf function | Input | Output structure | What it gives |
|---|---|---|---|---|
| 46 `SamrQueryInformationDomain2` | `policy._query_domain` → `samr_password_policy` | domain handle, info class `DomainPasswordInformation` (1) | `SAMPR_DOMAIN_INFO_BUFFER` → `DOMAIN_PASSWORD_INFORMATION` | min length, history length, properties (complexity bit), max/min age. Preferred over opnum 8. |
| 8 `SamrQueryInformationDomain` | `policy._query_domain` (fallback) | domain handle, info class | `SAMPR_DOMAIN_INFO_BUFFER` | Same fields as opnum 46; used when 46 is unavailable. |
| 56 `SamrGetDomainPasswordInformation` | `samr_get_domain_password_information` | (handle-light; server-only) | `DOMAIN_PASSWORD_INFORMATION` | min length + properties, without opening a domain handle. |
| 44 `SamrGetUserDomainPasswordInformation` | `samr_get_user_password_information` | **user handle** (open the target user first) | `DOMAIN_PASSWORD_INFORMATION` | The **per-user** effective min length, with any PSO (fine-grained policy) resolved for that account. |
| 67 `SamrValidatePassword` | (oracle path) | `SAM_VALIDATE_AUTHENTICATION_INPUT_ARG` and friends | validation output arg | Validates a candidate password against stored policy. **Gated over NP**: reach via `ncacn_ip_tcp`. |

`DOMAIN_PASSWORD_INFORMATION` is the common return ([MS-SAMR] 2.2.3.5):

```c
typedef struct _DOMAIN_PASSWORD_INFORMATION {
    unsigned short   MinPasswordLength;
    unsigned short   PasswordHistoryLength;
    unsigned long    PasswordProperties;   // bit 0x1 = DOMAIN_PASSWORD_COMPLEX
    OLD_LARGE_INTEGER MaxPasswordAge;       // negative 100-ns ticks
    OLD_LARGE_INTEGER MinPasswordAge;
} DOMAIN_PASSWORD_INFORMATION;
```

The distinction between opnum 56 (domain-wide) and opnum 44 (per-user, PSO-resolved) is the reason passwolf reads both: a user covered by a fine-grained password policy can have a different minimum length from the domain default, and only opnum 44 reflects it.

## USERINFO structure guide

The reset and read paths carry their payload in a tagged union, `SAMPR_USER_INFO_BUFFER` ([MS-SAMR] 2.2.6.29). The `USER_INFORMATION_CLASS` value selects which arm of the union is present, and for password work the arm decides **what secret travels and how it is protected**. This table lists every class in the spec enum (and the two internal-only classes the leaked source adds), with the key question answered: can it carry a cleartext password, an NT/LM hash, or neither?

| Value | USER_INFORMATION_CLASS | Union struct | Carries cleartext pw? | Carries NT/LM hash? | Protection | Used for |
|---|---|---|:--:|:--:|---|---|
| 1 | UserGeneralInformation | `SAMPR_USER_GENERAL_INFORMATION` | no | no | none | read attributes |
| 2 | UserPreferencesInformation | `SAMPR_USER_PREFERENCES_INFORMATION` | no | no | none | read/write attributes |
| 3 | UserLogonInformation | `SAMPR_USER_LOGON_INFORMATION` | no | no | none | read |
| 4 | UserLogonHoursInformation | `SAMPR_USER_LOGON_HOURS_INFORMATION` | no | no | none | read/write |
| 5 | UserAccountInformation | `SAMPR_USER_ACCOUNT_INFORMATION` | no | no | none | read |
| 6 | UserNameInformation | `SAMPR_USER_NAME_INFORMATION` | no | no | none | read/write |
| 7 | UserAccountNameInformation | `SAMPR_USER_A_NAME_INFORMATION` | no | no | none | read/write |
| 8 | UserFullNameInformation | `SAMPR_USER_F_NAME_INFORMATION` | no | no | none | read/write |
| 9 | UserPrimaryGroupInformation | `USER_PRIMARY_GROUP_INFORMATION` | no | no | none | read/write |
| 10 | UserHomeInformation | `SAMPR_USER_HOME_INFORMATION` | no | no | none | read/write |
| 11 | UserScriptInformation | `SAMPR_USER_SCRIPT_INFORMATION` | no | no | none | read/write |
| 12 | UserProfileInformation | `SAMPR_USER_PROFILE_INFORMATION` | no | no | none | read/write |
| 13 | UserAdminCommentInformation | `SAMPR_USER_ADMIN_COMMENT_INFORMATION` | no | no | none | read/write |
| 14 | UserWorkStationsInformation | `SAMPR_USER_WORKSTATIONS_INFORMATION` | no | no | none | read/write |
| 16 | UserControlInformation | `USER_CONTROL_INFORMATION` | no | no | none | read/write (account flags) |
| 17 | UserExpiresInformation | `USER_EXPIRES_INFORMATION` | no | no | none | read/write |
| 18 | **UserInternal1Information** | `SAMPR_USER_INTERNAL1_INFORMATION` | no | **yes (NT + LM OWF)** | DES with SMB session key | **set-by-hash reset** (`SAMR_HASH`); also the DSRM payload |
| 19 | UserInternal2Information | *(internal)* | no | yes | trusted-client only | netlogon/SAM internal path; **not remotely settable** |
| 20 | UserParametersInformation | `SAMPR_USER_PARAMETERS_INFORMATION` | no | no | none | read/write |
| 21 | UserAllInformation | `SAMPR_USER_ALL_INFORMATION` | no | **yes (OWF fields)** | DES with SMB session key | bulk attributes; can carry NT/LM OWF for a reset |
| 23 | UserInternal4Information | `SAMPR_USER_INTERNAL4_INFORMATION` | **yes** | no | RC4 with SMB session key | cleartext reset (unsalted; passwolf prefers the `_NEW` form) |
| 24 | UserInternal5Information | `SAMPR_USER_INTERNAL5_INFORMATION` | **yes** | no | RC4 with SMB session key | cleartext reset (password-only, unsalted) |
| 25 | **UserInternal4InformationNew** | `SAMPR_USER_INTERNAL4_INFORMATION_NEW` | **yes** | no | RC4 + MD5 salt, SMB session key | **RC4 reset** (`SAMR_RC4`) |
| 26 | UserInternal5InformationNew | `SAMPR_USER_INTERNAL5_INFORMATION_NEW` | **yes** | no | RC4 + MD5 salt, SMB session key | salted cleartext reset (password-only); aliases to Internal4New server-side |
| 30 | UserResetInformation | `SAMPR_USER_RESET_INFORMATION` | no | no | none | reset-state attributes (impacket-only enum entry; see deviations) |
| 31 | **UserInternal7Information** | `SAMPR_USER_INTERNAL7_INFORMATION` | **yes** | no | AES-256 AEAD, SMB session key | **AES reset** (`SAMR_AES`), password alone |
| 32 | **UserInternal8Information** | `SAMPR_USER_INTERNAL8_INFORMATION` | **yes** | no | AES-256 AEAD, SMB session key | **AES reset** (`--reset-info-class internal8`), password wrapped in all-info |

(`UserInternal3Information` and `UserInternal6Information` also appear in the leaked source but are trusted-client-only and have no public enum value or remote dispatch; they are not in the table.)

### The password-bearing structures

These are the only structures that move a secret. Each is the contents of one union arm above.

`SAMPR_USER_INTERNAL1_INFORMATION` ([MS-SAMR] 2.2.6.23) is the **hash** carrier:

```c
typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
    ENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword;  // NT hash, DES'd with the SMB session key
    ENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword;  // LM hash, same
    unsigned char NtPasswordPresent;                   // nonzero ⇒ NT field is valid
    unsigned char LmPasswordPresent;                   // nonzero ⇒ LM field is valid
    unsigned char PasswordExpired;
} SAMPR_USER_INTERNAL1_INFORMATION;
```

This is the structure that lets you reset (or DSRM-set) straight from a hash: no cleartext ever crosses the wire and no policy check runs.

`SAMPR_ENCRYPTED_USER_PASSWORD` / `SAMPR_USER_PASSWORD` ([MS-SAMR] 2.2.6.21) is the **RC4 cleartext** carrier used by the RC4/OEM changes (55/54) and the unsalted reset classes (23/24):

```c
typedef struct _SAMPR_USER_PASSWORD {
    wchar_t       Buffer[256];   // cleartext sits at the END of the buffer
    unsigned long Length;        // bytes of cleartext, counted from the end
} SAMPR_USER_PASSWORD;           // encrypted as 516 bytes → SAMPR_ENCRYPTED_USER_PASSWORD
```

`SAMPR_ENCRYPTED_USER_PASSWORD_NEW` / `SAMPR_USER_PASSWORD_NEW` ([MS-SAMR] 2.2.6.22) adds a 16-byte **unencrypted salt** mixed into the RC4 key; used by the `_NEW` reset classes (25/26):

```c
typedef struct _SAMPR_USER_PASSWORD_NEW {
    WCHAR Buffer[256];
    ULONG Length;
    UCHAR ClearSalt[16];   // random, NOT encrypted; mixed via MD5 into the key
} SAMPR_USER_PASSWORD_NEW;
```

`SAMPR_ENCRYPTED_PASSWORD_AES` / `SAMPR_USER_PASSWORD_AES` ([MS-SAMR] 2.2.6.32) is the modern **AES** carrier used by the AES change (73) and AES resets (Internal7/8):

```c
typedef struct _SAMPR_ENCRYPTED_PASSWORD_AES {
    UCHAR     AuthData[64];        // HMAC-SHA-512 signature
    UCHAR     Salt[16];            // random; AES IV + PBKDF2 salt
    ULONG     cbCipher;
    [size_is(cbCipher)] PUCHAR Cipher;  // AES-256 of SAMPR_USER_PASSWORD_AES
    ULONGLONG PBKDF2Iterations;
} SAMPR_ENCRYPTED_PASSWORD_AES;

typedef struct _SAMPR_USER_PASSWORD_AES {
    USHORT PasswordLength;         // cleartext length in bytes
    WCHAR  Buffer[SAM_MAX_PASSWORD_LENGTH];  // cleartext at the START here
} SAMPR_USER_PASSWORD_AES;
```

The key difference for the **change** (opnum 73) versus the **reset** (Internal7/8): both use this exact structure and the same AES cipher, but the change derives its key from the **old password's NT hash** via PBKDF2 (so the caller need only know the old password), while the reset uses the **SMB session key** (so the caller needs the force-change right and an SMB session). Same wire structure, different key source, which is the whole change-versus-reset distinction in one line.

## Summary: functions per purpose, inputs and outputs

The single table to keep. "Required to obtain first" is what you must have in hand before the call succeeds; "you get back" is the result.

### Change a password (proves the old password; no special rights; works on a null session)

| Function | Opnum | Required to obtain first | You get back | On Server 2025 |
|---|---|---|---|---|
| `change_aes` (`SAMR_AES`) | 73 | old password (→ PBKDF2 key), new password, server + account name | NTSTATUS | **works** |
| `change_diag` (`SAMR_DIAG`) | 63 | old NT hash, new password, account name | NTSTATUS **+ effective policy + failure reason** | works (undocumented) |
| `change_rc4` (`SAMR_RC4`) | 55 | old NT hash, new password, account name | NTSTATUS | blocked |
| `change_oem` (`SAMR_OEM`) | 54 | old LM hash (must be stored), new password, account name | NTSTATUS | blocked |
| `change_des` (`SAMR_DES`) | 38 | **user handle** (`SamrOpenUser`), old NT/LM hash, new password **or** new NT/LM hash | NTSTATUS | blocked |

### Reset a password (no old password; needs force-change right; pipe-only)

| Function | Opnum / class | Required to obtain first | You get back | Cipher |
|---|---|---|---|---|
| `reset_aes` (`SAMR_AES`) | 58 / UserInternal7 (31) | privileged SMB bind → **session key**, user handle, new password | NTSTATUS | AES-256 |
| `_build_internal8` via `reset_set_information` (`--reset-info-class internal8`) | 58 / UserInternal8 (32) | session key, user handle, new password | NTSTATUS | AES-256 |
| `reset_rc4` (`SAMR_RC4`) | 58 / UserInternal4New (25) | session key, user handle, new password | NTSTATUS | RC4 + salt |
| `reset_hash` (`SAMR_HASH`) | 37 / UserInternal1 (18) | session key, user handle, **NT hash** (+ optional LM) | NTSTATUS (policy bypassed) | DES |
| `reset_dsrm` (`DSRM`) | 66 | server handle on the DC, new password | NTSTATUS (sets the DC's recovery account) | DES |

### Collect the password policy

| Function | Opnum | Required to obtain first | You get back |
|---|---|---|---|
| `samr_password_policy` | 46 (or 8) | domain handle | min length, history, complexity bit, max/min age |
| `samr_get_domain_password_information` | 56 | server connection | min length + properties (no domain handle needed) |
| `samr_get_user_password_information` | 44 | **user handle** for the target | per-user min length (PSO-resolved) |
| `SamrValidatePassword` | 67 | candidate password; **TCP transport** | policy-validation verdict |

## Source deviations (spec vs impacket vs leaked source vs live)

Documented because they bite anyone building against a single source:

- **Opnum 63 is undocumented but live.** The spec marks it `Opnum63NotUsedOnWire`; the 2003 IDL defines it as `SamrUnicodeChangePasswordUser3` (between Connect4=62 and Connect5=64), and both the 2022 and 2025 DCs answer it. impacket has no definition for it. passwolf reaches it as `SAMR_DIAG`.
- **impacket stops at opnum 67.** It has no NDR definition or `hSamr*` helper for opnums 73 (AES change), 74, 77, or 63. Calling AES-SAMR or the diagnostic change means hand-building the request, which passwolf does.
- **impacket's `USER_INFORMATION_CLASS` lacks the AES levels.** Its enum ends at `UserInternal5InformationNew = 26` and uniquely includes `UserResetInformation = 30`; it has **no** `UserInternal7Information (31)` / `UserInternal8Information (32)`, and its `SAMPR_USER_INFO_BUFFER` union has no arm for them. The current spec enum and union, by contrast, include 31/32 and **omit** 30. So the AES reset structures (`SAMPR_USER_INTERNAL7/8_INFORMATION`, `SAMPR_ENCRYPTED_PASSWORD_AES`) are absent from impacket entirely.
- **No high-level helper ≠ not callable.** impacket ships only two synthetic password helpers built on opnum 58, `hSamrSetPasswordInternal4New` (RC4 reset via UserInternal4New) and `hSamrSetNTInternal1` (hash reset via UserInternal1), plus `hSamrUnicodeChangePasswordUser2` for opnum 55. Everything else password-related is assembled from the raw request classes.
- **"NotUsedOnWire" but present.** Opnums 42, 43, 60, 61 answer an empty stub with a bad-stub fault (present), even though the spec reserves them for local use. The dispatch slot exists on the live build; the method still is not meant for remote callers. Opnum 59 is `access_denied` (present but privilege-gated).
- **Build delta.** Opnum 77 (`SamrAccountIsDelegatedManagedServiceAccount`) is present on Server 2025 but `access_denied` on Server 2022, a concrete build-to-build difference.
- **Opnum 67 is pipe-gated.** `SamrValidatePassword` returns `access_denied` over `ncacn_np` on both DCs (matches [MS-SAMR] note `<8>`, Vista SP2+); use `ncacn_ip_tcp`.

## Cross-checked against live DLL extractions and reimplementations

Beyond the spec and impacket, the opnum table and structures above were verified against the interface as it actually ships, using public GitHub sources. These either confirm the documented layout or expose things neither the spec nor impacket lists.

Sources used:

- **NtApiDotNet IDL extracted from a live Windows 11 `samsrv.dll`, build 26200.7840** (`marcosd4h/DeepExtractRuntime`, `rpc_data/rpc_clients_26200_7840/12345778-1234-ABCD-EF00-0123456789AC_1.0.cs`): the proc table and NDR structs as the current DLL marshals them.
- **A full independent SAMR reimplementation** (`TheManticoreProject/Manticore`, one Go file per opnum): an outside party's opnum→method map.
- **Leaked / open headers and servers**: `reactos/reactos` (`samsrv/samrpc.c`), `tongzx/nt5src` and `selfrender/Windows-Server-2003` (`ds/inc/samrpc.h`, `sam.idl`), and `tyranid/WindowsRpcClients` (NtObjectManager extraction of Win7 `samsrv.dll`).
- **AES-change PoCs**: `decoder-it/ChgPass` and `M0nster3/RpcsDemo` (`ms-samr.h` with the `SamrUnicodeChangePasswordUser4` definition).

What the extractions confirm or add:

- **Opnum 63 is a real, current method, not just a 2003 artifact.** The build-26200 DLL exports `SamrUnicodeChangePasswordUser3` at opnum 63 with exactly the documented shape: the `SamrUnicodeChangePasswordUser2` inputs (server name, `SAMPR_ENCRYPTED_USER_PASSWORD`, old-NT verifier) **plus** an extra `AdditionalData` buffer, returning two `out` parameters, `EffectivePasswordPolicy` (`DOMAIN_PASSWORD_INFORMATION`) and `PasswordChangeInfo` (`USER_PWD_CHANGE_FAILURE_INFORMATION`). ReactOS and the NT5/2003 headers carry the same signature. So the diagnostic-change value passwolf uses (`SAMR_DIAG`) is present on everything from Server 2003 to Windows 11 26200, despite the spec marking it `Opnum63NotUsedOnWire`.
- **Every opnum slot has a real name, and the interface ends at 79.** The build-26200 proc table names all 80 opnums (0–79), including the ones the spec marks `OpnumNNNotUsedOnWire`: opnum 4 `SamrShutdownSamServer`, 42/43 `SamrTestPrivateFunctions{Domain,User}`, 59/60 `Samr{Set,Get}BootKeyInformation`, 61 `SamrConnect3`, 63 `SamrUnicodeChangePasswordUser3`, 68 `SamrQueryLocalizableAccountsInDomain`, 69 `SamrPerformGenericOperation`, 70 `SamrSyncDSRMPasswordFromAccount`, 71 `SamrLookupNamesInDomain2`, 72 `SamrEnumerateUsersInDomain2`, 75 `SamrQueryLapsManagedAccount`, 76 `SamrLapsSysprepCleanup`, 78 `SamrFindOrCreateShadowAdminAccount`, 79 `SamrIsShadowAdminAccount`. There is no opnum 80 or 81. Opnum-to-name alignment is anchored against known opnums (41 `SamrGetDisplayEnumerationIndex`, 44 `SamrGetUserDomainPasswordInformation`, 73 `SamrUnicodeChangePasswordUser4`, 77 `SamrAccountIsDelegatedManagedServiceAccount`), so the 0-based proc index equals the opnum exactly. The `TheManticoreProject/Manticore` reimplementation corroborates the remotely-documented names.
- **Three new password-adjacent methods surface in the named slots.** `SamrSyncDSRMPasswordFromAccount` (70) and `SamrQueryLapsManagedAccount` (75) touch credentials (DSRM sync, LAPS password read), and `SamrLapsSysprepCleanup` (76) is LAPS housekeeping. They are local/newer and were not remotely callable on the probed DCs, so passwolf does not use them, but they are the closest "hidden" password surface beyond the documented set.
- **`SAMPR_ENCRYPTED_PASSWORD_AES` is confirmed field-for-field from the live DLL.** The extracted struct lays out as `AuthData[64]` @0x00, `Salt[16]` @0x40, `cbCipher` (int32) @0x50, `Cipher` (conformant pointer, size `cbCipher`) @0x58, `PBKDF2Iterations` (int64) @0x60, byte-for-byte the [MS-SAMR] 2.2.6.32 layout. Used by `SamrUnicodeChangePasswordUser4` (73) and the Internal7/8 reset arms.
- **The live `SamrSetInformationUser2` info-class union is a superset of both the spec and impacket.** The 26200 DLL marshals selectors **1–14, 16–26, 28, 29, 30, 31, 32**. That means it carries, all at once: the AES levels **31 / 32** (which impacket lacks), `UserResetInformation` **30** (which the current public spec union omits), `UserInternal2Information` **19**, and three more arms (**22, 28, 29**) that have **no public `USER_INFORMATION_CLASS` name in either the spec or impacket**. Selectors 22/28/29 are the remotely-marshalled face of the internal levels the leaked source calls UserInternal3/UserInternal6 and friends; they are reachable shapes on the wire, not just in-process constants. This is the most concrete "hidden" finding: a current DC's set-user union accepts more info classes than any public enum documents.
