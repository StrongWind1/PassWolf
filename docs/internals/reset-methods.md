# Reset methods in detail

A reset overwrites an account secret by privilege. The caller proves nothing about the old password and must hold reset rights on the target. This page documents every reset method `passwolf reset` speaks, at the wire level: the opnum, the information level, the spec section, the cipher, and the server behavior. The shared cryptography (the password buffers, the DES OWF wrap, the SAMR AEAD, the SMB session key) lives in [crypto](crypto.md); status decoding lives in [errors](errors.md); how the SAMR channel is bound lives in [transport](transport.md). For the operator view of the same methods, see [the passwolf reset guide](../guide/reset.md), and for picking among them see [the methods matrix](../methods.md).

The standard `--method` choices `passwolf reset` exposes are `auto`, `samr-aes`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash`, `kpasswd`, and `ldap`. The AES all-information form (`UserInternal8`) and the other settable info classes that lack a `--method` shortcut are reached through the advanced `--reset-info-class` / `--reset-opnum` flags described in [Advanced opnum and info-class selection](#advanced-opnum-and-info-class-selection). The DSRM reset is not a `--method` value; it is selected by the `--dsrm` flag.

!!! note "The reset signature: no old password, no min-age, no history"
    Every method on this page writes the new secret without supplying the old one. The defining server-side consequence is that minimum password age and password history are not enforced, because both are properties of the old value or the change shape. Length and complexity are still validated for the cleartext methods, because those are properties of the new value. The hash-set reset bypasses even those.

## How the SAMR resets are dispatched

All the SAMR cleartext and hash resets share one entry point in `src/passwolf/reset.py`: `_run_samr_reset` opens a SAMR channel as the privileged `--auth-as-user` caller, resolves the target to an open user handle (`samr.open_user_handle`, the connect / open-domain / lookup-name / open-user chain), then either dispatches by `--method` (`_run_standard_samr_reset`) or, when `--reset-info-class` is set, sends that exact class via `_run_advanced_samr_reset`. The Kerberos, LDAP, and DSRM resets have their own paths and are not handle-based in the same way.

The SAMR reset interface is `SamrSetInformationUser2` (opnum 58, [MS-SAMR] 3.1.5.6.4) for the cleartext and AES levels, and `SamrSetInformationUser` (opnum 37, [MS-SAMR] 3.1.5.6.5) for the hash-set level. SamrSetInformationUser (opnum 37) and SamrSetInformationUser2 (opnum 58) are the same server routine: [MS-SAMR] 3.1.5.6.5 states opnum 37 "MUST behave as with a call to SamrSetInformationUser2," and the leaked server body of opnum 58 is a thin veil whose implementation is return SamrSetInformationUser(...). Either opnum can carry any UserInternal info class, because dispatch is on the UserInformationClass, never on the opnum; passwolf's opnum-per-class split is a code convention, not a wire requirement. The information level inside the request selects the cipher path and what is overwritten.

!!! warning "The cleartext info levels require the SMB named pipe, not TCP"
    The six cleartext-bearing levels (UserInternal4/5, their `_NEW` salted forms, and the AES UserInternal7/8) plus the hash-set level UserInternal1 all key their cipher on the 16-byte SMB session key ([MS-SAMR] 3.1.2.4 / 3.2.2.3). That key only exists over RPC-over-SMB. [MS-SAMR] 2.1 states RPC clients MUST use only RPC over SMB for these levels. Over `ncacn_ip_tcp` there is no SMB session key, so the buffer cannot be keyed. In `reset.py` the channel carries `session_key`; when it is `None` (the TCP transport), the SAMR reset helpers in `samr.py` raise `MethodUnavailable` with a message telling the operator to use `--transport smb`. This is why `--transport smb` is the default and why TCP is only useful for the change methods.

## samr-aes (UserInternal7, opnum 58, AES, password only)

=== "What it does"

    The compact AES cleartext reset. `passwolf reset --method samr-aes` calls `SamrSetInformationUser2` (opnum 58) with `UserInformationClass = UserInternal7Information` (value 31, `constants.USER_INTERNAL7_INFORMATION`). UserInternal7 carries the password buffer plus a `PasswordExpired` byte and no `SAMPR_USER_ALL_INFORMATION` block, so it is the "password only" AES form. This is the first SAMR rung `auto` tries (see below). Implemented in `samr.reset_aes`.

=== "Wire and crypto"

    The buffer is `SAMPR_ENCRYPTED_PASSWORD_AES` ([MS-SAMR] 2.2.6.32): a 64-byte `AuthData`, a 16-byte `Salt`, a 4-byte `cbCipher`, the `cbCipher`-byte `Cipher`, and an 8-byte `PBKDF2Iterations`. The construction is AEAD-AES-256-CBC-HMAC-SHA512 per [MS-SAMR] 3.2.2.4. The content-encryption key is the 16-byte SMB session key directly, not a PBKDF2-derived key. `PBKDF2Iterations` is sent as 0 and ignored by the server. The blob is built by `samr._aes_reset_blob`, shared with the internal8 reset; the AEAD itself is detailed in [crypto](crypto.md).

=== "Server processing"

    Per [MS-SAMR] 3.1.5.6.4.1, the server reduces UserInternal7 to UserInternal8 with `I1.WhichFields = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED` (note the AES path sets no LM bit), then applies the decrypted cleartext. It recomputes the NT (and, where applicable, LM) OWFs and the Kerberos keys from the cleartext, so the account gets full credential material. Requires `USER_FORCE_PASSWORD_CHANGE` on the handle ([MS-SAMR] 3.1.5.6.4.2). The expiry byte is driven by `--expire` (see [the expiry control](#the-expiry-control)).

!!! note "AES is the only change cipher Server 2025 accepts, and the reset mirrors it"
    The UserInternal7 AEAD construction is the same as the opnum 73 AES change (single nonce reused as IV and wire `Salt`, `Cipher` is the raw AES-CBC output) except the content-encryption key is the SMB session key directly rather than a PBKDF2 derivation of the old NT hash. The AES levels are not in the pre-AES leaked source; their cryptography rests on [MS-SAMR] 3.2.2.4 and 2.2.6.32, and the path was live-validated returning STATUS_SUCCESS on both a Server 2022 and a Server 2025 DC.

## UserInternal8 (internal8, opnum 58, AES wrapping UserAllInformation)

Reached with `passwolf reset --reset-info-class internal8` (it has no `--method` shortcut; `--reset-opnum 37` or `58` picks the opnum, default 58). It calls `SamrSetInformationUser2` (opnum 58) with `UserInformationClass = UserInternal8Information` (value 32, `constants.USER_INTERNAL8_INFORMATION`). UserInternal8 is the all-information form of the AES reset: it carries a `SAMPR_USER_ALL_INFORMATION` block (`I1`) alongside the same `SAMPR_ENCRYPTED_PASSWORD_AES` `UserPassword` field that samr-aes uses ([MS-SAMR] 2.2.6.31). The status label the tool emits for this path is `samr-internal8-op58` (or `samr-internal8-op37`). Built by `samr._build_internal8` and dispatched through `samr.reset_set_information`.

The password is always taken from the separate `UserPassword` field, not from `I1`. `samr._build_internal8` zeroes every pointer member of the `I1` block (`_clear_all_information`) and sets only `I1.WhichFields = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED` and `I1.PasswordExpired`, exactly as the server's own UserInternal7-to-UserInternal8 mapping does ([MS-SAMR] 3.1.5.6.4.1). The cipher, the key, and the access right are identical to samr-aes; the only difference is the wire shape carries the all-information block. Use samr-aes for a plain password reset; the internal8 reset exists for the all-information form. Like samr-aes it needs the named-pipe session key.

## samr-rc4-unsalted (UserInternal4, opnum 58, RC4 without salt)

`passwolf reset --method samr-rc4-unsalted` calls `SamrSetInformationUser2` (opnum 58) with `UserInformationClass = UserInternal4Information` (value 23, `constants.USER_INTERNAL4_INFORMATION`). It is the legacy, unsalted sibling of `samr-rc4`: the password buffer is the 516-byte `SAMPR_ENCRYPTED_USER_PASSWORD` RC4-encrypted with the SMB session key directly ([MS-SAMR] 3.2.2.1), with no MD5 salt mixed into the key. The salted `samr-rc4` (`UserInternal4InformationNew`) is preferred; this exists for completeness and for servers that accept only the unsalted level. Implemented in `samr.reset_rc4_unsalted`, which delegates to the generic builder.

## Advanced opnum and info-class selection

`--reset-info-class` and `--reset-opnum` expose the generic reset directly, overriding `--method`. They send any of the eight settable password-bearing `USER_INFORMATION_CLASS` values over either opnum (37 or 58), the full 2×8 matrix, through one entry point, `samr.reset_set_information`. The info class names map as: `internal1` (18), `userall` (21), `internal4` (23), `internal5` (24), `internal4new` (25), `internal5new` (26), `internal7` (31), `internal8` (32). The hash classes (`internal1`, `userall`) take `--target-new-hash`, or a cleartext `--target-new-password` that is hashed locally into its NT OWF; the rest require `--target-new-password`. The per-class builder enforces which is needed.

Because dispatch is on the info class and not the opnum (see above), every class works over either opnum on a spec-compliant DC; the only practical limit is that older servers reject the newer `*new`/AES levels on opnum 37, which is exactly why the native Windows client reserves those for opnum 58. The server also re-maps several classes (`internal5`→`internal4`, `internal5new`→`internal4new`, `internal7`→`internal8`, and `internal1` into the all-information block per [MS-SAMR] 3.1.5.6.4.1), so a mapped class and its target produce an identical stored result and differ only in the bytes on the wire.

## samr-rc4 (UserInternal4InformationNew, opnum 58, RC4 plus MD5 salt)

`passwolf reset --method samr-rc4` calls `SamrSetInformationUser2` (opnum 58) with `UserInformationClass = UserInternal4InformationNew` (value 25, `constants.USER_INTERNAL4_INFORMATION_NEW`). This is the salted RC4 cleartext reset `auto` tries after AES in its ladder (see below). Implemented in `samr.reset_rc4`.

| Property | Value |
|---|---|
| Opnum | 58 (`SamrSetInformationUser2`) |
| Info level | UserInternal4InformationNew = 25 |
| Buffer | `SAMPR_ENCRYPTED_USER_PASSWORD_NEW`, 532 bytes ([MS-SAMR] 2.2.6.22): 516 RC4-encrypted bytes plus a 16-byte trailing clear salt |
| Cipher | RC4 over the first 516 bytes; the 16-byte salt rides in the clear |
| Key | MD5(ClearSalt + 16-byte SMB session key), per [MS-SAMR] 3.2.2.2 |
| Spec | [MS-SAMR] 3.1.5.6.4.5 |
| Access | `USER_FORCE_PASSWORD_CHANGE` |

The salt only feeds the per-buffer MD5 key derivation; the session key is still the root key material. `samr.reset_rc4` builds the buffer with `crypto.build_rc4_md5_password_buffer`, clears the `I1` all-information block, and sets `WhichFields = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED`. It is built directly rather than via the impacket helper so that `--expire` is honored (the impacket helper hardcodes the expiry flag). Like the AES resets, it needs the SMB session key and therefore the SMB transport.

??? note "Why the `_NEW` (salted) form and not the plain UserInternal4Information"
    The unsalted UserInternal4Information (level 23) keys RC4 directly on the session key, which exposes a known-keystream weakness fixed by the salted form ([MS-SAMR] 3.2.2.2 derives MD5(salt + key) per buffer). `passwolf reset` sends the `_NEW` salted form. The server collapses both to the same Internal4 processing path, so the stored result is identical.

## samr-hash (UserInternal1, opnum 37, the identical sibling of SamrSetInformationUser2 opnum 58, sets NT and optionally LM OWF directly)

`passwolf reset --method samr-hash`, or supplying `--target-new-hash` with `auto`, calls `SamrSetInformationUser` (opnum 37) with `UserInformationClass = UserInternal1Information` (value 18, `constants.USER_INTERNAL1_INFORMATION`). This writes the NT one-way function directly, and the LM OWF too when `--target-new-hash LM:NT` is given. Implemented in `samr.reset_hash`.

The payload is `SAMPR_USER_INTERNAL1_INFORMATION` ([MS-SAMR] 2.2.6.23): a 16-byte `EncryptedNtOwfPassword`, a 16-byte `EncryptedLmOwfPassword`, and three flag bytes `NtPasswordPresent`, `LmPasswordPresent`, `PasswordExpired`. Each OWF half is DES-encrypted with the 16-byte SMB session key per [MS-SAMR] 2.2.11.1.1, so this path also needs the named pipe. `samr.reset_hash` always sets `NtPasswordPresent = 1`; it sets `LmPasswordPresent = 1` and the encrypted LM half only when an LM hash was supplied, otherwise it sends a zeroed LM field with the present flag clear.

!!! danger "samr-hash is the full policy bypass"
    Because no cleartext password is ever evaluated, the server runs no length, complexity, history, or minimum-age check on this path. A hash that would be rejected as a weak password if sent as cleartext is accepted here. The server processes UserInternal1 exactly as UserAllInformation carrying the three password `WhichFields` bits ([MS-SAMR] 3.1.5.6.4.1), and the path requires `USER_FORCE_PASSWORD_CHANGE` ([MS-SAMR] 3.1.5.6.4.2). This is the canonical "set a hash from a hash" reset. UserInternal1 (level 18) is not the only raw-OWF set path: UserAllInformation (level 21) can also carry the NT and LM OWF fields, and both levels were live-confirmed to set the NT hash and log in on Server 2022 and 2025 over opnum 37 and 58. passwolf uses the dedicated UserInternal1 class.

!!! warning "Set-hash leaves Kerberos AES keys stale"
    Setting the RC4 NT hash directly does not regenerate the account's Kerberos AES keys, which are derived from the cleartext at a normal set ([MS-SAMR] 3.1.1.8.11.6, Primary:Kerberos-Newer-Keys; impacket warns "User no longer has valid AES keys for Kerberos, until they change their password again"). The account keeps stale or absent AES keys until a subsequent cleartext set or change, so a hash-set account may fail Kerberos preauth even though NTLM with the new hash works. A set-hash reset with `--expire` also writes `pwdLastSet = 0` (must-change-at-next-logon, [MS-SAMR] 3.1.5.6.4.2), which blocks non-interactive logon until the holder sets a real password. The set-hash reset itself returns success on both Server 2022 and Server 2025 (it is a reset, unaffected by the Server 2025 legacy-change opnum block). When you need the value usable for non-interactive logon immediately, pass `--no-expire` so `pwdLastSet` is not zeroed. See [the passwolf reset guide](../guide/reset.md) for the operator workflow.

## kpasswd (Kerberos set protocol, version 0xFF80)

`passwolf reset --method kpasswd` resets over the Kerberos kpasswd service on port 464, RFC 3244, using the set framing identified by protocol version 0xFF80. Implemented in `kpasswd.reset`, which adapts impacket's `kpasswd.setPassword`. The caller authenticates as itself (the `--auth-as-user` principal) to the `kadmin/changepw` service and names the target inside the request.

The wire framing is byte-identical to a kpasswd change; the only thing that makes it a set is the presence of the optional `targname` (the target principal, an NT_PRINCIPAL with the target sAMAccountName) and `targrealm` (the uppercased target realm) inside the encrypted `ChangePasswdData`. Per [MS-KILE] 3.1.5.12, "If the fields are present, then this is a request to set a password and the initial flag is not required. If the fields are absent, then this is a password change." `kpasswd.reset` passes the caller as `caller_user`/`caller_domain` and the target as `target_user`/`target_domain`, so impacket populates both fields.

!!! note "Cleartext only over kpasswd, no SMB session key"
    The new password travels as a cleartext UTF-8 octet string, protected only by the Kerberos KRB-PRIV layer (key usage 13), not by any SAMR-style buffer. There is no way to supply a hash over kpasswd; a hash-only reset must use samr-hash. kpasswd is not wrapped in SMB3 transport encryption and does not use the SMB session key, so it is independent of the `--transport` choice. The set requires reset (force-change) rights on the target, the same right as the SAMR force-set, enforced server-side by `SamISetPasswordForeignUser2`. Like every reset it skips minimum age and history; complexity and length still apply.

## ldap (unicodePwd single replace, sealed 389)

`passwolf reset --method ldap` resets by a single LDAP Modify Replace of the `unicodePwd` attribute on the target object ([MS-ADTS] 3.1.1.3.1.5.1). Implemented in `ldap.reset`. The shape is the entire signal: a reset is one replace with one value; a change is a delete of the old value followed by an add of the new. The replace shape carries no old password, so the operation is gated entirely on the User-Force-Change-Password control access right (rightsGuid `00299570-246d-11d0-a768-00aa006e0529`), which resolves to the same directory ACE as the SAMR `USER_FORCE_PASSWORD_CHANGE` bit.

The value is the new password wrapped in ASCII double quotes and encoded UTF-16LE, BER-encoded as an octet string ([MS-ADTS] 3.1.1.3.1.5.1). `ldap._quoted` produces exactly `'"' + password + '"'` encoded `utf-16-le`. There is no cipher at the LDAP layer; the password is recoverable cleartext inside the encrypted channel, which is why the channel itself must be confidential.

!!! warning "The connection must be confidential, and sealed 389 is the default"
    [MS-ADTS] 3.1.1.3.1.5.1 requires a 128-bit-or-better encrypted connection: TLS, or a SASL bind that negotiated 128-bit sealing. Integrity-only signing does not satisfy it, because the DC measures cipher strength, not signing. `passwolf reset` defaults to plain LDAP on 389 with a SASL sign-and-seal bind (`ldap._connect` builds an `ldap://` URL, which keeps the impacket signing/sealing path active), and only switches to LDAPS on 636 when you pass `--ldaps`. This is the decisive correctness fix over impacket's `changepasswd.py`, which hardcodes `ldaps://` and so fails against a DC with no LDAPS certificate. The target is resolved from its sAMAccountName to a distinguishedName before the Modify (`ldap._resolve_dn`).

## dsrm (SamrSetDSRMPassword, opnum 66, DC-local recovery account)

The `--dsrm` flag resets the DC-local Directory Services Restore Mode recovery password through `SamrSetDSRMPassword` (opnum 66, [MS-SAMR] 3.1.5.13.6). This is its own selector: when `--dsrm` is set it overrides `--method`. Implemented in `samr.reset_dsrm`, dispatched by `_run_dsrm_reset` in `reset.py`. This account is the local Administrator of the DC SAM that is used when the DC boots into restore mode; it is not a domain account in Active Directory.

| Property | Value |
|---|---|
| Method | `SamrSetDSRMPassword`, opnum 66 |
| Spec | [MS-SAMR] 3.1.5.13.6 |
| Account | RID 500 (`DOMAIN_USER_RID_ADMIN = 0x1F4`); the CLI `--target-user` is ignored because the RID is fixed in code to 500; the server enforces `UserId = 0x1F4` ([MS-SAMR] 3.1.5.13.6 constraint 3, footnote <70>; live-validated: STATUS_SUCCESS on both DCs) and rejects any other RID with STATUS_NOT_SUPPORTED (leaked Server 2003 `dsrmpwd.c:320`) |
| Wire value | the new NT OWF DES-encrypted under a key derived from the RID per [MS-SAMR] 2.2.11.1.3 |
| Transport | SMB named pipe only |
| Authorization | membership in BUILTIN\\Administrators (S-1-5-32-544), not an object ACL |

There is no object handle: opnum 66 takes a raw RPC binding, names the account solely by the RID, and runs no SamrConnect/OpenDomain/OpenUser chain. `samr.reset_dsrm` computes the NT OWF of `--target-new-password`, derives the 14-byte DES key from the little-endian RID 0x1F4 (`crypto.rid_to_des_key`), DES-encrypts the OWF, sends `Unused = NULL` and `UserId = DOMAIN_USER_RID_ADMIN`; the server enforces `UserId = 0x1F4` and rejects any other RID with STATUS_NOT_SUPPORTED (leaked Server 2003 `dsrmpwd.c:320`). impacket ships no helper and no crypto for this method, so it is built by hand.

!!! danger "DSRM is SMB-only and DC-local"
    [MS-SAMR] 3.1.5.13.6 requires RPC over SMB for this method; on Vista SP2 / 2008 SP2 and later a TCP attempt is rejected with `RPC_S_ACCESS_DENIED`. `_run_dsrm_reset` rejects `--transport tcp` up front: when the channel has no SMB session key it raises `MethodUnavailable` telling you to use `--transport smb`, for a clear error rather than a server fault. The operation touches only the local safe-boot registry hive of the DC you contacted; it does not replicate, so to set the DSRM password across multiple DCs you call each one. It is a reset, so it runs no complexity, history, or minimum-age check. It was live-validated returning STATUS_SUCCESS on both lab DCs over the named pipe.

## The expiry control

`--expire` (the default) and `--no-expire` set the must-change-at-next-logon flag on the cleartext and hash SAMR resets. In `reset.py` the resolved `expire` boolean is threaded into `samr.reset_aes`, the `internal8` reset (`samr._build_internal8` via `reset_set_information`), `reset_rc4`, and `reset_hash`, which write the `PasswordExpired` byte as 1 or 0. Per [MS-SAMR] 3.1.5.6.4.2, a nonzero `PasswordExpired` sets `pwdLastSet = 0` (force change at next logon); a zero value, when the password is past the effective max age, sets `pwdLastSet` to the current time. The expiry control does not apply to the kpasswd or LDAP resets, which carry no expiry field, and `--no-expire` is the lever for the set-hash Kerberos-key interaction described above.

## auto: the full method ladder

`--method auto` is the default. For a cleartext new password it tries every reset method in a fixed order and takes the first that succeeds; supplying only `--target-new-hash` skips the cleartext rungs and drops straight to samr-hash. The logic is `_run_auto_reset` (and its SAMR tail `_auto_samr_ladder`) in `reset.py`. The order is:

1. **kpasswd**: the Kerberos set protocol (RFC 3244). Tried first because it is the cleanest cross-domain path and carries no SMB session-key dependency.
2. **ldaps**: the LDAP `unicodePwd` replace over TLS on 636.
3. **ldap**: the same replace over a sealed connection on 389.
4. **samr-aes**: the compact AES cleartext reset (opnum 58 + UserInternal7). A `SamrConnect5` preflight (`samr.supports_aes`, opnum 64, AES feature bit `0x10`, [MS-SAMR] 2.2.7.15 / 3.2.2.4) skips this rung when the DC explicitly does not advertise the AES password buffer.
5. **samr-rc4**: the salted RC4 cleartext reset (UserInternal4InformationNew).
6. **samr-rc4-unsalted**: the unsalted RC4 cleartext reset (UserInternal4Information).
7. **samr-hash**: the set-hash reset (UserInternal1). It writes the NT OWF derived from the cleartext, so it is the last resort that still applies when every cleartext rung was rejected (for example by a password policy), and it is the only rung that can apply a hash-only secret.

Each rung is attempted in turn. A rung is *taken* only when it raises no availability error and returns `STATUS_SUCCESS`; an unavailable method (a closed port, an RPC fault, a `MethodUnavailable`), or any non-success status, is logged at INFO and `auto` moves to the next. The four SAMR rungs share a single named-pipe channel opened once. If every rung fails, `auto` raises `MethodUnavailable` with the accumulated per-rung reasons.

!!! tip "What auto reports"
    The outcome records the method that actually ran, not `auto`. If the ladder fell through you will see, for example, `samr-rc4` in the output; run with `-v` to see each rung that was skipped and why. The default output format is pretty; `--format text` and `--format json` are also available. See [output formats](../guide/output-formats.md) and [the methods matrix](../methods.md) for the full per-method comparison, and [errors](errors.md) for how the returned NTSTATUS is decoded.
