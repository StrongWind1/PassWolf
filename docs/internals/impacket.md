# Compared to impacket

passwolf exists because impacket's `examples/changepasswd.py` cannot perform a SAMR (NTLM-hash) change on a Windows Server 2025 domain controller, and is missing or incomplete on several other paths a complete password tool needs. impacket can still change a password on Server 2025 over non-SAMR protocols (its LDAP `unicodePwd` change works there where the DC offers LDAPS, live-confirmed, and the kpasswd change protocol is not gated); what it lacks is the AES SAMR change that 2025 requires for a SAMR-level change. This page is the per-method correctness audit: what impacket lacks or gets wrong on the wire, and what passwolf does instead. Every claim here is grounded in a file:line in the audited impacket tree, an opnum, or a Microsoft Open Specification section, and is cross-checked against live runs on a Server 2022 DC (build 20348) and a Server 2025 DC (build 26100). The full source audit lives in `/root/changepassword/scripts/17-impacket-correctness-audit.md` and the live evidence in `/root/changepassword/scripts/18-live-lab-verification-log.md`.

The audited build is impacket 0.13.1 dev, commit 9a5621d4, which self-reports `v0.14.0.dev0`. All `samr.py`, `crypto.py`, and `changepasswd.py` line numbers below refer to that tree.

!!! note "Scope"
    This compares correctness of the password change and reset wire formats, not feature surface in general. impacket is a large and mature library; the gaps below are specific to the SAMR change and reset opnums, the Kerberos kpasswd path, and the LDAP unicodePwd path that `changepasswd.py` exposes.

## Gap table

| Area | What impacket does | Consequence | What passwolf does |
|---|---|---|---|
| AES SAMR change (opnum 73, `SamrUnicodeChangePasswordUser4`) | Absent. No NDRCALL class, no dispatch entry past opnum 67 (samr.py:2465-2466), no `SAMPR_ENCRYPTED_PASSWORD_AES` struct, no AEAD-AES or PBKDF2 in crypto.py | Cannot perform a SAMR change on a Server 2025 DC: the legacy change opnums it does have are refused (ACCESS_DENIED) and the AES one that works is missing (impacket's LDAP and kpasswd changes are not gated) | `samr-aes`: hand-built opnum 73 with the [MS-SAMR] 2.2.6.32 struct and the 3.2.2.4 AEAD-AES-256-CBC-HMAC-SHA512 / 3.2.2.5 PBKDF2 derivation |
| AES SAMR reset info levels (UserInternal7 / UserInternal8) | Absent. Enum stops at 26 plus a non-spec 30 (samr.py:1100-1104); no Internal7/8 structs | Falls back to the RC4/MD5-salt cleartext reset; cannot send the strongest set path | `samr-aes` reset: opnum 58 with `UserInternal7Information`, same AEAD as opnum 73 but CEK is the SMB session key directly |
| OEM change (opnum 54, `SamrOemChangePasswordUser2`) | Struct present and correct (samr.py:2261-2268) but no `hSamrOemChangePasswordUser2` helper | Callable only by hand; `changepasswd.py` never reaches it | `samr-oem`: builds the LM-keyed RC4 buffer and verifier directly |
| DES cross-encryption change (opnum 38, `SamrChangePasswordUser`) | `hSamrChangePasswordUser` hardcodes `LmPresent=0`, emits only spec combination 3, and never runs the cross-encryption retry (samr.py:2791-2835) | Cannot build combinations 1 or 2 and never recovers from `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` | `samr-des`: hand-builds opnum 38 and performs the cross-encryption retry on the cross-encryption-required status |
| Diagnostic change (opnum 63, `SamrUnicodeChangePasswordUser3`) | Absent. No opnum 63 class | No access to the structured policy-rejection reason | `samr-diag`: opnum 63 with the two `[out]` diagnostic structures |
| kpasswd change / set | Plaintext-only, correct framing (changepasswd.py:257-312) | Cannot take an NT hash; this is a protocol property, not a defect | Same plaintext requirement (`kpasswd` method); it is a property of RFC 3244 |
| LDAP change / set | Hardcodes `ldaps://` (changepasswd.py:608) | ECONNRESET on a DC with no LDAPS certificate; no plain-389 fallback | `ldap`: defaults to sealed LDAP on 389 with a SASL sign-and-seal bind; `--ldaps` is opt-in |

## The AES change: opnum 73, the load-bearing gap

This is the single highest-impact difference. impacket has no AES SAMR change.

Reading the code confirms the absence on three independent points (see scripts/17 "SamrUnicodeChangePasswordUser4 (opnum 73, AES)"):

- The OPNUMS dispatch map ends at `67 : (SamrValidatePassword, ...)` (samr.py:2465) with the closing brace at samr.py:2466; the only change entries are opnums 38, 54, and 55 (samr.py:2442, 2456, 2457). With no NDRCALL class, a call cannot be serialized.
- There is no `SAMPR_ENCRYPTED_PASSWORD_AES` struct ([MS-SAMR] 2.2.6.32) and no `Internal7`/`Internal8` symbols anywhere in samr.py.
- crypto.py has the DES OWF path and AES-CMAC primitives but no AEAD-AES-256-CBC-HMAC-SHA512 and no PBKDF2-HMAC-SHA512 CEK derivation ([MS-SAMR] 3.2.2.5).

!!! danger "Server 2025 hard failure"
    On a Server 2025 DC the legacy RC4/DES change opnums 38, 54, and 55 are refused before any password check. A wrong old password against each returns STATUS_ACCESS_DENIED (0xC0000022), not STATUS_WRONG_PASSWORD (0xC000006A), proving the rejection happens at method dispatch. Opnum 73 (AEAD-AES) is the only SAMR change the DC accepts. Because impacket has only the legacy change opnums 38, 54, and 55, it cannot perform a SAMR change on Server 2025; its non-SAMR change protocols are unaffected by this gate, so its LDAP `unicodePwd` change still works there (live-confirmed) and the kpasswd change protocol is not gated. This is the CVE-2021-33757 / KB5004605 hardening with enforcement now on by default, as described in Microsoft's "Beyond RC4 for Windows authentication" guidance.

The differential, observed live on both DCs (scripts/18, "Legacy change-method enforcement differential"):

| Opnum | Method | Payload crypto | Server 2022 | Server 2025 |
|---|---|---|---|---|
| 38 | `SamrChangePasswordUser` | DES OWF cross-encryption | 0xC000006A WRONG_PASSWORD (enabled) | 0xC0000022 ACCESS_DENIED (refused) |
| 54 | `SamrOemChangePasswordUser2` | RC4 keyed by old LM hash | 0xC000006A WRONG_PASSWORD (enabled) | 0xC0000022 ACCESS_DENIED (refused) |
| 55 | `SamrUnicodeChangePasswordUser2` | RC4 keyed by old NT hash | 0xC000006A WRONG_PASSWORD (enabled) | 0xC0000022 ACCESS_DENIED (refused) |
| 73 | `SamrUnicodeChangePasswordUser4` | AEAD-AES-256-CBC-HMAC-SHA512 | STATUS_SUCCESS | STATUS_SUCCESS |

passwolf builds opnum 73 by hand. The construction has three non-obvious points the prose spec does not state, pinned by cross-checking the Samba interoperable reference: the single 16-byte nonce is reused as the PBKDF2 salt, the AES-CBC IV, and the struct `Salt` field; the `Cipher` field is the raw AES-CBC ciphertext with the IV not prepended; and the two key-derivation strings include their trailing NUL in the HMAC message. See [Change methods](change-methods.md) for the full opnum 73 walkthrough and [the methods matrix](../methods.md) for where it sits relative to the legacy opcodes.

## The AES reset info levels: UserInternal7 / UserInternal8

The reset side has the sibling gap. impacket's `USER_INFORMATION_CLASS` enum carries the cleartext levels (`UserInternal4Information = 23` through `UserInternal4InformationNew = 25`, samr.py:1100-1103) plus a non-spec `UserResetInformation = 30`, but stops there. There is no `UserInternal7Information` (31) or `UserInternal8Information` (32), no matching structs, and no `SAMPR_ENCRYPTED_PASSWORD_AES` (scripts/17, "SamrSetInformationUser2 AES levels").

The spec calls these the best cleartext-password choice: "Using SamrSetInformationUser2 with UserInternal8Information and UserInternal7Information is the best choice that a client can make for setting a cleartext password through this protocol, because the cryptography used is the strongest in this protocol" ([MS-SAMR] 5.1, Security Considerations for Implementers). impacket cannot send it; its strongest reset path is the RC4-buffer-with-MD5-salt level built by `hSamrSetPasswordInternal4New` (samr.py:2966-3006), which is a faithful [MS-SAMR] 3.2.2.1 (RC4 cipher) / 3.2.2.2 (MD5-salt RC4 key) implementation over the 2.2.6.22 _NEW buffer but not the AES one.

passwolf's `samr-aes` reset sends opnum 58 with `UserInternal7Information` (level 31). The AEAD construction is identical to opnum 73 except the content-encryption key is the 16-byte SMB session key directly rather than a PBKDF2 derivation, and `PBKDF2Iterations` is 0. The union arm is `UserInfo31 = { EncryptedPasswordAES password; uint8 password_expired }`, per the Samba `samr.idl` layout. This was live-validated to STATUS_SUCCESS on both DCs. See [Reset methods](reset-methods.md).

!!! note "internal8"
    passwolf reset also exposes the UserInternal8Information (level 32) all-information AES reset form via `--reset-info-class internal8`, which wraps a SAMPR_USER_ALL_INFORMATION block alongside the AES-encrypted password in one info level. The plain `samr-aes` reset is the UserInternal7Information (level 31) password-only form; the two are alternative single-level forms, not a combined one. Default output is `pretty`; both decode the NTSTATUS so a policy rejection is distinguishable from a transport or method failure.

## The OEM change: opnum 54 has a struct but no helper

impacket's struct `SamrOemChangePasswordUser2` is present and spec-correct, with `opnum = 54` and the four IDL fields (samr.py:2261-2268), response at samr.py:2270-2273, and dispatch entry at samr.py:2456 ([MS-SAMR] 3.1.5.10.2). What is missing is the convenience helper: a grep for `hSamrOemChangePasswordUser2` returns only the struct, response, and dispatch lines, never a helper.

The sibling `hSamrUnicodeChangePasswordUser2` is not reusable for this because it hardcodes the NT-hash path (RC4 under the old NT hash, UTF-16LE encoding, NT-hash verifier, samr.py:2867-2880). A caller must build the OEM request by hand: RC4-encrypt the buffer under `ntlm.LMOWFv1(old)` and set the verifier to `crypto.SamEncryptNTLMHash(oldLmHash, newLmHash)`. The primitives exist; only the wrapper is absent.

passwolf's `samr-oem` method builds that request directly. Because the OEM/LM path keys on the LM hash and an OEM-codepage encoding of the password, it needs the cleartext old password and cannot be driven from an NT hash alone (this is noted in passwolf change's help and in the README limitations).

## The DES cross-encryption change: opnum 38 hardcodes LmPresent=0

impacket's `hSamrChangePasswordUser` (samr.py:2791-2835) is correct on the central point that this method uses DES throughout, not RC4: every encrypted field goes through `crypto.SamEncryptNTLMHash`, the DES two-block construction of [MS-SAMR] 2.2.11.1.1 (crypto.py:336-352). No RC4 is constructed on this path.

The limit is in the combination it builds. The helper hardcodes spec combination 3 only: it sets `LmPresent = 0`, both LM pointers NULL, `NtPresent = 1`, `LmCrossEncryptionPresent = 1`, and emits `NewLmEncryptedWithNewNt` as the cross term (samr.py:2824-2833). It cannot build combination 1 or 2, and it never implements the `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` / `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` retry loop of [MS-SAMR] 3.1.5.10.1.

!!! note "Not a bug on modern AD"
    Against a domain that stores the NT hash, combination 3 authenticates, so impacket's hardcoded combination is an incompleteness rather than a defect on this path. It matters when the server demands a cross-encryption that combination 3 does not supply.

passwolf's `samr-des` method hand-builds opnum 38 and performs the cross-encryption retry: when the DC returns the cross-encryption-required status, it re-issues the request with the cross term the server asked for, rather than failing outright. Opnum 38 also needs a user handle, which is the operational catch impacket's own header acknowledges ("Cannot get a handle on user object", changepasswd.py:37-38).

## The diagnostic change: opnum 63 is absent

impacket has no class for opnum 63 (`SamrUnicodeChangePasswordUser3`); its OPNUMS table ends at 67 with no entry for 63 (samr.py:2465-2466). This method is undocumented in MS-SAMR (marked Opnum63NotUsedOnWire) but is present in the leaked SAMR IDL and is reachable on both live DCs. It takes the same argument list as opnum 55 plus an extra `[in, unique]` AdditionalData pointer and two `[out]` structures: the effective password policy and a structured change-failure reason. That structured reason is exactly the feedback a change tool wants, and impacket cannot get it.

passwolf's `samr-diag` method issues opnum 63 with those two out-params. Live, it returns STATUS_SUCCESS on Server 2022 and STATUS_ACCESS_DENIED on Server 2025, the same legacy-change block that refuses opnum 55, because it reuses opnum 55's RC4 buffer and the enforcement is keyed on the wire crypto, not the opnum.

## kpasswd: plaintext-only by protocol

impacket's kpasswd path is correct. `KPassword._changePassword` and `_setPassword` refuse a non-plaintext new password (changepasswd.py:262, 297) and the change path refuses to target another user (changepasswd.py:257-259). That is the protocol, not a defect: kpasswd carries the cleartext new password inside a KRB-PRIV (RFC 3244) and has no hash path.

One framing detail worth recording: impacket sends Kerberos kpasswd protocol version 0xFF80 (the set-password framing) for both change and set, distinguishing the two only by the presence of `targname`/`targrealm` (kpasswd.py:48, 169-173, 210). passwolf follows the same protocol: both its `kpasswd` change and its `kpasswd` reset are sent with the 0xFF80 framing, the change omitting `targname`/`targrealm` and the reset including the target name and realm, and like impacket it requires a plaintext new password. Both kpasswd operations work on Server 2025; Kerberos is unaffected by the SAM-RPC legacy-change enforcement.

## LDAP: impacket hardcodes ldaps://

The LDAP modify shapes are correct in both tools: a change is a `delete` of the old quoted UTF-16LE `unicodePwd` value plus an `add` of the new value in one ModifyRequest, and a reset is a single `replace` (changepasswd.py:673-683), per Microsoft's quoted-UTF-16LE rule.

The defect is the transport. `LdapPassword.connect` hardcodes the LDAPS scheme:

```
ldapURI = "ldaps://" + self.address   # changepasswd.py:608
```

There is no fallback to plain LDAP on 389 with SASL sign-and-seal and no StartTLS option. On a DC with no LDAPS server certificate the connect is reset at the TCP layer (errno 104), so both `-protocol ldap` change and reset fail with ECONNRESET. The impacket ECONNRESET on ldaps:// was confirmed live on the Server 2022 DC for both change (probe 03) and reset (probe 06) at a time when neither DC offered an LDAPS certificate (nxc "No TLS cert" on both DCs, scripts/18 "no LDAPS" finding), so the same hardcoded-ldaps:// failure applied to both. After an LDAPS certificate was later provisioned on both DCs, impacket's `-protocol ldap` change succeeded against the Server 2025 DC (a real change, confirmed by an SMB login with the new password), proving the LDAP change path is not affected by the Server 2025 legacy-SAMR-change hardening. The defect that remains is the missing sealed-389 fallback: impacket's LDAP change still fails on any DC without an LDAPS certificate, which is the common case, because the password write itself does not require a certificate. It works fine over plain 389 with SASL sealing, where the channel is encrypted by the GSS-API wrap rather than by TLS.

passwolf's `ldap` method defaults to plain LDAP on 389 with a SASL sign-and-seal bind, so it works on a DC without an LDAPS certificate. LDAPS on 636 is available but opt-in via the `--ldaps` flag on both `passwolf change` and `passwolf reset`. Like impacket, the LDAP path needs the cleartext old (for the delete value on a change) and new password; the quoted unicodePwd value cannot be formed from a hash.

??? note "What impacket gets right (for completeness)"
    The audit is not all gaps. impacket's opnum 55 helper is correct on the NT path (RC4 buffer keyed by the old NT hash, DES verifier, 516-byte buffer per 2.2.6.21). `hSamrSetNTInternal1` (opnum 37, UserInternal1) correctly DES-encrypts the NT OWF under the SMB session key per [MS-SAMR] 2.2.6.23, though it drops the LM half and leaves `PasswordExpired` at 0. `crypto.SamEncryptNTLMHash` is the correct DES construction of 2.2.11.1.1 and is shared correctly by opnums 38, 55, and Internal1. Note that this opnum 37 helper does not give impacket an AES set: the AES set levels (UserInternal7 = 31, UserInternal8 = 32) are selected by the info class, not the opnum, so having opnum 37 (the identical sibling of SamrSetInformationUser2 opnum 58) buys nothing without the level-31/32 structs. UserInternal1 (level 18) is also not the only remotely-usable raw-OWF set path: UserAllInformation (level 21) can carry the NT/LM OWF fields too, and both were live-confirmed to set the NT hash and log in on Server 2022 and 2025 over opnum 37 and opnum 58. The kpasswd framing and the LDAP modify shapes are correct. passwolf reuses these correct primitives where they apply and replaces only the paths that are missing, incomplete, or buggy.

## Live validation summary

Every passwolf method was validated against live DCs, and every impacket gap above was confirmed both by reading the source and by observing the wire. The campaigns are recorded in `/root/changepassword/scripts/18-live-lab-verification-log.md`.

- Server 2022 (build 20348) and Server 2025 (build 26100): the two modern DCs carry the headline finding. Legacy SAMR change opnums 38/54/55 return WRONG_PASSWORD on 2022 (the crypto check is reached) but ACCESS_DENIED on 2025 (refused at dispatch). The AES change (opnum 73) and the AES reset (UserInternal7, level 31) both return STATUS_SUCCESS on both DCs. On Server 2025 this was validated by a real password change with Kerberos confirmation: an AS-REQ with the new password issued a TGT while the old password returned KDC_ERR_PREAUTH_FAILED, ruling out the NTLM grace window as a false positive. On Server 2022 the change was confirmed by SMB login plus a password-history STATUS_PASSWORD_RESTRICTION, which proves the AEAD/old-password verify passed before policy was applied. The DES-OWF set-hash reset (opnum 37) and the cleartext RC4 reset (opnum 58) still succeed on 2025, so impacket can reset over SAMR but cannot do a SAMR change there (its LDAP change still works on 2025). opnum 37 and opnum 58 are interchangeable ([MS-SAMR] 3.1.5.6.5: opnum 37 "MUST behave as with a call to SamrSetInformationUser2"); the info class, not the opnum, selects the operation, so the 37-with-hash and 58-with-RC4 pairing here is a passwolf/impacket convention rather than a wire requirement (see [Reset methods](reset-methods.md)). The diagnostic opnum 63, the OEM change opnum 54, the DSRM reset opnum 66, LDAP over plain 389, and kpasswd change and set were all exercised on these DCs as well.
- Legacy matrix (NT 4.0, XP SP3, Server 2003, Server 2008): used to validate the OEM/LM and RAP paths that only function on older hosts. The cleartext RAP change (opcode 115) works end to end only on NT 4.0 and is a no-op on Server 2003/2008/XP; the RC4-OEM RAP change (opcode 214) was live-validated working end to end on NT 4.0 (not exercised on the other legacy hosts). The direct LM-only `SamrChangePasswordUser` (opnum 38) the RAP gateway issues internally succeeds on Server 2003 over `\pipe\samr` even where the gateway's xactsrv handler does not, isolating the failure to the gateway. These hosts also confirmed an impacket tooling defect against NT 4.0: `getSessionKey()` returns the raw NT OWF instead of MD4(NT OWF) when key exchange was not negotiated, corrupting session-key-encrypted SAMR set on NT4.

!!! warning "On 2025, impacket's SAMR change is blocked; its LDAP and kpasswd changes still work"
    The practical takeaway: against a Server 2025 DC, impacket can still reset a password (the session-key reset levels are unaffected by the change hardening) and can change one over LDAP (live-confirmed) or the kpasswd protocol, but it cannot perform a SAMR change, because its only SAMR change opnums are the blocked legacy ones and it lacks opnum 73. passwolf implements opnum 73, so the SAMR change works too on Server 2025, and its LDAP change defaults to sealed 389 so it needs no LDAPS certificate where impacket's hardcoded `ldaps://` does.

## See also

- [Change methods](change-methods.md): the per-opnum change implementation, including the hand-built opnum 73 and the cross-encryption retry on opnum 38.
- [Reset methods](reset-methods.md): the reset info levels, including the AES UserInternal7 path impacket lacks.
- [The methods matrix](../methods.md): every method side by side with its opnum, crypto, and DC acceptance.
