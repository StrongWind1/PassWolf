# Change methods in detail

A change proves knowledge of the account's current secret and writes a new one. No privilege on the target is required: the proof is cryptographic, not an ACL check. This page documents each change method `passwolf change` exposes at the wire level: its opnum, spec section, request structure, cryptography, what knowledge it proves, and how it behaves across server versions. The selection logic that picks among them lives in [`change.py`](../guide/change.md); the shared cryptographic primitives are in [crypto.md](crypto.md); the transports that carry these calls are in [transport.md](transport.md); the NTSTATUS values they return are in [errors.md](errors.md). The one-line matrix of every method is in [methods.md](../methods.md).

Each method is reachable through `passwolf change --method NAME`, or selected automatically by `--method auto` (the default). The exact `--method` names are `samr-aes`, `samr-rc4`, `samr-oem`, `samr-des`, `samr-diag`, `kpasswd`, `ldap`, `netlogon-aes`, `netlogon-des`, `rap`, and `rap-oem`. Machine and trust accounts (`--account machine`, `--account trust`) change over the Netlogon secure channel; a machine account's AUTO additionally falls back to the SAMR AES cleartext change (see [netlogon-aes and netlogon-des](#netlogon-aes-and-netlogon-des-machine-and-trust-changes)).

!!! note "Source files"
    The SAMR changes are implemented in `src/passwolf/samr.py`, the Kerberos change in `src/passwolf/kpasswd.py`, the LDAP change in `src/passwolf/ldap.py`, the machine and trust changes in `src/passwolf/netlogon.py`, and the legacy SMB1 changes in `src/passwolf/rap.py`. The dispatch by account kind and method is in `src/passwolf/change.py`.

## samr-aes: SamrUnicodeChangePasswordUser4 (opnum 73)

The AES-protected SAMR change, and the only SAMR change a Windows Server 2025 DC accepts once it disables the legacy methods. impacket does not implement it, so `passwolf change` builds the NDR struct and the AEAD by hand (`samr.change_aes`).

**Spec:** [MS-SAMR] 3.1.5.10.4 (method), 2.2.6.32 (the `SAMPR_ENCRYPTED_PASSWORD_AES` struct and the decrypted `SAMPR_USER_PASSWORD_AES` plaintext), 3.2.2.4 (AEAD algebra), 3.2.2.5 (PBKDF2 key derivation), 2.2.1.18 (constants).

**Wire structure:** the method takes no context handle. It carries `ServerName`, `UserName` (the sAMAccountName), and one `EncryptedPassword` of type `SAMPR_ENCRYPTED_PASSWORD_AES`: a 64-byte `AuthData` HMAC tag, a 16-byte `Salt`, a 4-byte `cbCipher` length, the variable `Cipher`, and an 8-byte `PBKDF2Iterations` count. The decrypted plaintext is the 514-byte `SAMPR_USER_PASSWORD_AES`: a little-endian 16-bit length, then the UTF-16LE password at the START of a 512-byte buffer with random fill after it. This password-first orientation is the reverse of every legacy RC4 buffer, which right-justifies the password.

**Cryptography:** AEAD-AES-256-CBC-HMAC-SHA512. The content-encryption key (CEK) is `PBKDF2(NT-hash-of-old-password, Salt, PBKDF2Iterations, dklen=16)` using HMAC-SHA-512 as the PRF ([MS-SAMR] 3.2.2.5). From the CEK, `enc_key` is the first 32 bytes of `HMAC-SHA-512(CEK, SAM_AES256_ENC_KEY_STRING)` and `mac_key` is the full 64 bytes of `HMAC-SHA-512(CEK, SAM_AES256_MAC_KEY_STRING)`. The Salt field is reused as the PBKDF2 salt AND the AES-CBC IV: one 16-byte nonce serves all three roles, and the Cipher field is the raw ciphertext with no IV prefix. `AuthData` is `HMAC-SHA-512(mac_key, 0x01 + IV + Cipher + 0x01)`. `passwolf change` sends `PBKDF2Iterations` of 10000 (`PBKDF2_ITERATIONS_DEFAULT`); the spec requires the count to be in the inclusive range 5000 to 1000000.

**What it proves:** knowledge of the old password's NT hash. The server re-derives the same CEK from its stored NT hash; if the client's CEK differs, the MAC verification fails and the server returns `STATUS_WRONG_PASSWORD` (0xC000006A). Because the CEK is keyed from the NT hash, a pass-the-hash change works: `--target-old-hash NTHASH` is sufficient.

??? note "Why the AEAD MAC is the verifier"
    Unlike opnum 55, this method carries no separate DES-encrypted OWF verifier block. The proof of knowledge is the successful HMAC-SHA-512 verification over the AES ciphertext: only a client that derived the CEK from the correct old NT hash produces a tag the server accepts. The minimum 514-byte decrypted length also defeats ciphertext truncation, which fails the size check and returns `STATUS_WRONG_PASSWORD`.

**Server-version behavior:** Server 2022 and Server 2025 both accept it (validated live). Server 2025 requires it: that DC refuses the legacy change opnums 38, 54, 55, and 63 with `STATUS_ACCESS_DENIED` (0xC0000022) before any password check, and accepts only opnum 73. This is the CVE-2021-33757 / KB5004605 hardening enforced by default. AUTO routes to AES whenever the DC advertises the AES password buffer.

!!! tip "How AUTO chooses AES versus RC4"
    `_auto_samr_change` runs a `SamrConnect5` SupportedFeatures preflight (`samr.supports_aes`, [MS-SAMR] 2.2.7.15 bit 0x10). When the DC explicitly does not advertise the AES buffer, AUTO goes straight to `samr-rc4`. Otherwise it tries `samr-aes` and keeps a fault-based fallback: an RPC fault (`MethodUnavailable`) or a `STATUS_NOT_SUPPORTED` reply from opnum 73 falls back to the RC4 change.

## samr-rc4: SamrUnicodeChangePasswordUser2 (opnum 55)

The legacy Unicode RC4 change, the method Windows clients historically used. Implemented through impacket's `hSamrUnicodeChangePasswordUser2` (`samr.change_rc4`).

**Spec:** [MS-SAMR] 3.1.5.10.3 (method), 2.2.6.21 (the 516-byte `SAMPR_ENCRYPTED_USER_PASSWORD` buffer), 3.2.2.1 (the RC4 buffer cipher), 2.2.11.1.1 (the DES OWF verifier).

**Wire structure:** no context handle. `ServerName`, `UserName`, then `NewPasswordEncryptedWithOldNt` (the 516-byte RC4 buffer), `OldNtOwfPasswordEncryptedWithNewNt` (the 16-byte DES verifier), an `LmPresent` flag, and the two LM-side fields. `passwolf change` sends `LmPresent = 0` and NULLs the two LM fields.

**Cryptography:** two ciphers in one PDU. The password buffer is RC4-encrypted, keyed by the 16-byte NT hash of the existing password ([MS-SAMR] 3.2.2.1); the new password is right-justified at the tail of the 512-byte buffer with a trailing 4-byte length. The verifier is the old NT OWF DES-encrypted under the new NT OWF ([MS-SAMR] 2.2.11.1.1).

**What it proves:** knowledge of the old NT hash. The server RC4-decrypts the buffer with the stored NT hash and checks the verifier round-trips, so the old password is never sent. Pass-the-hash capable: `--target-old-hash` provides the NT hash directly.

**Server-version behavior:** accepted on Server 2022 and earlier. Server 2025 refuses it outright with `STATUS_ACCESS_DENIED` (the legacy RC4 change gate). This is the method AUTO falls back to when the DC does not advertise the AES buffer.

## samr-oem: SamrOemChangePasswordUser2 (opnum 54)

The OEM/LM RC4 change, the downlevel sibling of opnum 55 that keys on the LM hash. impacket has no helper for it, so the request is hand-built (`samr.change_oem`).

**Spec:** [MS-SAMR] 3.1.5.10.2 (method), 2.2.6.21 (the OEM-encoded password buffer), 2.2.11.1.1 (the DES verifier).

**Wire structure:** no context handle. `ServerName`, `UserName`, then `NewPasswordEncryptedWithOldLm` (the 516-byte RC4 OEM buffer) and `OldLmOwfPasswordEncryptedWithNewLm` (the 16-byte DES verifier). The verifier field is a referent pointer; `passwolf change` assigns the raw 16 bytes directly, matching impacket's own convention for these OWF fields.

**Cryptography:** the buffer holds the uppercased ANSI (OEM-codepage) new password, right-justified, RC4-encrypted under the 16-byte old LM hash. The verifier is the old LM OWF DES-encrypted under the new LM OWF.

**What it proves:** knowledge of the old password as cleartext. Because the LM one-way function cannot be recovered from an NT hash, this method requires the cleartext old password and cannot run pass-the-hash; `passwolf change` raises `MethodUnavailable` when only `--target-old-hash` is supplied.

!!! warning "Needs a stored LM hash"
    The target account must store an LM hash (`dBCSPwd`), which `NoLMHash` domains (the modern default) do not. On a current directory this method fails with `STATUS_WRONG_PASSWORD` regardless of whether the caller knows the password. Server 2025 additionally refuses the opnum with `STATUS_ACCESS_DENIED`.

## samr-des: SamrChangePasswordUser (opnum 38)

The original NT 3.1-era change, hash-only on every field, with DES OWF cross-encryption. Built by hand with a cross-encryption retry loop (`samr.change_des`) because impacket's `hSamrChangePasswordUser` hardcodes `LmPresent = 0` and never sends the NT cross-encryption term, which is wrong for some stored-hash states.

**Spec:** [MS-SAMR] 3.1.5.10.1 (method), 2.2.11.1.1 (the DES OWF construction). The two cross-encryption statuses are in the [MS-SAMR] 2.2.1.15 status table.

**Wire structure:** this is the one SAMR change that operates on an open user handle, so `passwolf change` first opens a handle with `USER_CHANGE_PASSWORD` (`samr.open_user_handle`). The request carries `UserHandle`, then four presence flags and their paired 16-byte OWF fields: `NtPresent` with `OldNtEncryptedWithNewNt` and `NewNtEncryptedWithOldNt`; `LmPresent` with the matching LM pair; `NtCrossEncryptionPresent` with `NewNtEncryptedWithNewLm`; and `LmCrossEncryptionPresent` with `NewLmEncryptedWithNewNt`. Every value on the wire is a 16-byte OWF hash, DES-encrypted under another hash; there is no cleartext buffer at all. A field named "X encrypted with Y" is `crypto.des_owf_encrypt(X, Y)`.

**Cryptography:** DES-ECB-LM only, on all fields ([MS-SAMR] 2.2.11.1.1). The 16-byte hash is split into two 8-byte blocks, each DES-encrypted under a 7-byte sub-key derived from the supplied 16-byte key. There is no RC4, no session key, and no salt: the only key material is the LM and NT hashes themselves. The field names read `<which-hash>EncryptedWith<which-key>`, so the plaintext is named first and the key second.

**What it proves:** knowledge of the old password's hashes. `passwolf change` always sends the NT authentication blobs (NT is always present); it adds the LM authentication blobs only when the cleartext old password is known, because the LM OWF cannot be recovered from an NT hash, so a pass-the-hash change is NT-only.

**Setting a raw NT hash:** this is the only change method that can write an arbitrary NT hash. `passwolf change --target-new-hash [LM:]NT` pins `--method samr-des` and builds an NT-only request: the old secret is proved by the NT OWFs (`OldNtEncryptedWithNewNt`, `NewNtEncryptedWithOldNt`), `LmPresent=0`, `NtCrossEncryptionPresent=0`, and `LmCrossEncryptionPresent=1` carries the new LM cross (`NewLmEncryptedWithNewNt`) keyed on the supplied LM half or the empty-LM placeholder, matching impacket's `hSamrChangePasswordUser` layout (`change_des(..., new_nt_hash=..., new_lm_hash=...)`). The server stores whatever NT OWF it is handed, so the change bypasses complexity and history, drops the account's Kerberos keys, and flags the password expired. The RC4/AES/OEM/diagnostic buffer changes cannot do this: they carry a cleartext password buffer from which the server recomputes the stored OWF, so they have no way to inject a chosen hash. Unlike the privileged `passwolf reset --target-new-hash` (UserInternal1, opnum 37), which forces the hash with `USER_FORCE_PASSWORD_CHANGE`, the change-by-hash proves the old secret in the request and so needs no privilege on the target.

??? note "The cross-encryption retry on a single-hash account"
    When the account stores only one of the two hashes, the server authenticates on the hash it has and asks for the missing new hash cross-encrypted. It signals this with `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` (0xC000017F, NT authenticated but the new LM hash is needed) or `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` (0xC000015D, LM authenticated but no NT hash is stored), per [MS-SAMR] 3.1.5.10.1. `change_des` catches each signal, sets the corresponding cross flag, and resends. An account is missing at most one stored hash, so at most one cross round is needed.

    A fresh request object is rebuilt per attempt, not mutated and resent. impacket NDRCALL structs do not re-serialize cleanly after a referent field is flipped from NULL to a pointer, so `_change_password_user_request` constructs a new struct for each try with the chosen presence flags. This is why `change_des` calls the builder again inside the retry loop rather than editing the prior request in place.

**Server-version behavior:** enabled on Server 2022 and earlier. Live-validated as `STATUS_SUCCESS` on Server 2022 (the combination-3 NT cross-encryption form, via `hSamrChangePasswordUser`) and as an LM-only change directly over `\pipe\samr` on Server 2003 and Windows NT 4.0; refused with `STATUS_ACCESS_DENIED` on Server 2025, like the other legacy change opnums. Windows XP and Server 2008 were never exercised with an opnum-38 SAMR change (they saw only the unrelated RAP opcode-115 no-op). The both-stored, NoLMHash, and pass-the-hash trio is the three theoretical spec hash-combinations plus the documented pass-the-hash protocol property, not a live-run test matrix. The handle requirement also means there is no anonymous path: the caller must already hold `USER_CHANGE_PASSWORD` on the target, which in a default directory means self.

## samr-diag: SamrUnicodeChangePasswordUser3 (opnum 63)

An undocumented RC4 change that doubles as a policy oracle: on a rejection it returns the effective password policy and a structured failure reason in the response body. The whole point of the method is to surface those diagnostics, so the wire call is issued in a way that keeps them (`samr.change_diag`).

**Spec:** the method has no published [MS-SAMR] section; it is grounded in the leaked `samrpc.idl` (line 1550) and the leaked Server 2003 `user.c` (lines 11565-11589), and confirmed live on Server 2022. The RC4 buffer and DES verifier reuse [MS-SAMR] 3.2.2.1 and 2.2.11.1.1.

**Wire structure:** no context handle. `ServerName`, `UserName`, `NewPasswordEncryptedWithOldNt` (the RC4 buffer), `OldNtOwfPasswordEncryptedWithNewNt` (the DES verifier), an `LmPresent` flag with its LM fields, and an `AdditionalData` field. `passwolf change` sends `LmPresent = 0` and a NULL `AdditionalData`. The response carries two extra out-structs alongside the `ErrorCode`: the effective `DOMAIN_PASSWORD_INFORMATION` and a `USER_PWD_CHANGE_FAILURE_INFORMATION`.

**Cryptography:** identical to `samr-rc4`. The new password buffer is RC4-encrypted under the old NT hash and the verifier is the old NT OWF DES-encrypted under the new NT OWF.

**The diagnostic oracle:** the server fills both out-structs only when the change fails with `STATUS_PASSWORD_RESTRICTION` and NULLs them on every other status (success, wrong old password, or the Server 2025 `ACCESS_DENIED`). When present, `change_diag` reports them in the outcome's `extra` map: `min_password_length`, `password_history_length`, `min_password_age_days` (the magnitude of the negative 100-nanosecond `MinPasswordAge` interval, rendered in days), and `change_failure_reason` (1 too short, 2 in history, 5 not complex, 0 too recent).

!!! note "Why call()/recv() instead of request()"
    The diagnostics arrive alongside a non-zero trailing NTSTATUS in the same response body. impacket's `DCERPC_v5.request()` raises on that non-zero status before the body can be parsed, which would discard the policy and reason. `change_diag` issues the call with `dce.call()` then `dce.recv()` and parses the raw stub by hand, so the diagnostics survive a rejected change. A genuine RPC fault (the opnum being unsupported) still raises and is reported as the method being unavailable.

**Server-version behavior:** the diagnostic fill is keyed purely on the top-level status being `STATUS_PASSWORD_RESTRICTION`, so it works the same on a live Server 2022 DC and in the leaked Server 2003 SAM handler (`user.c:11565-11589`), so it is not version-conditional. Server 2025 refuses opnum 63 outright with `STATUS_ACCESS_DENIED` (the same legacy RC4 change gate), so the diagnostics are reachable only on Server 2022 and earlier. AUTO does not select this method; pin it with `--method samr-diag`. The same oracle is exposed by `passwolf policy` for reading policy without changing anything.

## kpasswd: Kerberos change protocol (port 464)

The RFC 3244 change-password operation as Windows implements it ([MS-KILE] 3.1.5.12). The principal changes its own password by talking to the KDC password service over port 464, with no SMB, no SAMR, and no domain join. `passwolf change` drives impacket's `kpasswd.changePassword` (`kpasswd.change`).

**Spec:** RFC 3244 (the protocol and the 6-byte request header), [MS-KILE] 3.1.5.12 (the change-versus-set distinction), [MS-KILE] 3.3.5.1.2 (`kadmin/changepw` as the fixed service principal).

**Wire structure:** a 6-byte big-endian header (`MessageLength`, `Version`, `ApReqLength`), then an AP-REQ for `kadmin/changepw`, then a KRB-PRIV carrying the encrypted `ChangePasswdData`. For a change, `ChangePasswdData` populates only `newpasswd`; the optional `targname` and `targrealm` are absent. Their absence is what makes the request a change rather than a set: the server demotes the operation to a change when those fields are missing, regardless of the version field.

!!! note "The version trap"
    The protocol version is 0x0001 for the legacy framing and 0xFF80 for the extended framing, and the server accepts both on input. impacket actually sends 0xFF80 for both change and set; the change-versus-set distinction is made solely by whether `targname`/`targrealm` are present, not by the version number. So "version 0x0001 means change" is a misreading: the version selects framing, and the extended framing is used for everything. The Windows server stamps its reply with version 0x0001.

**Cryptography:** there is no password-specific cipher. The new password travels as cleartext UTF-8 bytes inside the KRB-PRIV encrypted part; confidentiality is entirely Kerberos message encryption, so it rides whatever enctype the AS exchange negotiated (AES when an AES key is available, RC4 from an NT hash). The authenticator uses key usage 11 under the ticket session key; the KRB-PRIV uses key usage 13 under a client-chosen subkey.

**What it proves:** the principal could not have obtained the AS-REP ticket for `kadmin/changepw` without its current password, NT hash, or key. The ticket is INITIAL by construction because it came straight from the AS, which satisfies the server's INITIAL-flag requirement for a change. The change runs the full SAM change path, so minimum password age and history apply.

**Server-version behavior:** not gated by the Server 2025 legacy RC4 SAMR change block. The change succeeds on both Server 2022 and Server 2025 (validated live), because the operation rides Kerberos message encryption and the server-side SAM change path rather than the RC4 SAMR password buffers the 2025 gate targets. Useful when SMB and SAMR are filtered but 464 is open.

## ldap: unicodePwd delete-old plus add-new (sealed 389)

A change over LDAP, written as a single Modify on `unicodePwd` that deletes the old quoted value and adds the new one ([MS-ADTS] 3.1.1.3.1.5). `passwolf change` drives impacket's `LDAPConnection.modify` (`ldap.change`).

**Spec:** [MS-ADTS] 3.1.1.3.1.5 (the `unicodePwd` change semantics).

**Wire structure:** one Modify with two ordered changes on `unicodePwd`: a delete of the old value and an add of the new value. Each value is the password wrapped in double quotes and encoded as UTF-16LE, the form the directory requires. The target's distinguishedName is resolved first from its sAMAccountName.

**Cryptography:** none at the application layer. The protection is the confidential channel. `passwolf change` defaults to plain LDAP on port 389 with a SASL sign-and-seal bind, which needs no certificate; `--ldaps` switches to LDAPS on 636. Defaulting to sealed 389 is the correctness fix over impacket's `changepasswd.py`, which hardcodes `ldaps://` and so fails on DCs without a server certificate.

**What it proves:** the directory verifies the deleted old value against the stored password, so the change needs the cleartext old password to form the delete value. `passwolf change` raises `MethodUnavailable` when only `--target-old-hash` is supplied. The add-plus-delete shape is what distinguishes a self-service change (both values, old verified) from a privileged reset (a single replace, no old value), which is the LDAP reset path.

**Server-version behavior:** not opnum-gated, so it is not affected by the Server 2025 legacy SAMR change block. It does require an authenticated bind and a confidential channel.

## netlogon-aes and netlogon-des: machine and trust changes

Machine accounts (`--account machine`) and trust accounts (`--account trust`) change their own secret over the Netlogon secure channel, not over SAMR. The account proves the current secret by building a secure channel keyed by it (`NetrServerReqChallenge` then `NetrServerAuthenticate3`), then writes the new secret. Two writes are supported: the AES buffer (opnum 30) and the legacy DES OWF (opnum 6). These live in `netlogon.py`; `_run_netlogon_change` runs the requested method, while AUTO walks a ladder in `_auto_machine_change`: Netlogon AES first, then -- for a machine account only -- the SAMR AES cleartext change (`netlogon-aes` -> `samr-aes` -> `netlogon-des`), then the Netlogon DES OWF. The SAMR rung exists because a computer is a user-class object: the SAMR AES change hands the DC the plaintext, so it regenerates every Kerberos key, a stronger result than the DES OWF. A trust account is not SAMR-changeable that way, so its ladder stays Netlogon AES -> Netlogon DES.

**Spec:** [MS-NRPC] 3.5.4.4.6 (`NetrServerPasswordSet2`, opnum 30), 3.5.4.4.7 (`NetrServerPasswordSet`, opnum 6), 2.2.1.3.7 (the `NL_TRUST_PASSWORD` buffer), 3.4.5.2.6 (Calling NetrServerPasswordSet2, the buffer construction and encryption), 3.1.4.4.1 (AES Credential, the AES-128 8-bit-CFB cipher).

!!! warning "The secure channel must be sealed first"
    Modern DCs enforce a sealed Netlogon channel (the post-CVE-2020-1472 hardening). After the `NetrServerAuthenticate3` bootstrap, `open_secure_channel` upgrades the binding to `RPC_C_AUTHN_NETLOGON` with `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`, alter-binds to send the `NL_AUTH_MESSAGE`, and sets the AES session key before either write is attempted.

### netlogon-aes: NetrServerPasswordSet2 (opnum 30)

The request carries `PrimaryName`, `AccountName`, `SecureChannelType`, `ComputerName`, a Netlogon `Authenticator`, and a `ClearNewPassword` of type `NL_TRUST_PASSWORD`: a 512-byte buffer with the password right-justified and a 4-byte trailing `Length`, 516 bytes in all. For a trust password the 12 bytes preceding the password are an `NL_PASSWORD_VERSION` block; for a machine account that region is random fill. `passwolf change` builds the buffer with `crypto.build_nl_trust_password` and encrypts it with AES-128-CFB8 (zero IV) under the secure-channel session key (`crypto.aes_cfb8_encrypt`). The `Authenticator` is the Netlogon credential advanced and re-encrypted with the session key.

### netlogon-des: NetrServerPasswordSet (opnum 6)

The older form. Same parameter shape, except the final parameter is `UasNewPassword`, a 16-byte `ENCRYPTED_NT_OWF_PASSWORD` rather than a buffer. `passwolf change` computes the NT OWF of the new password and DES-encrypts it under the session key (`crypto.des_owf_encrypt`), then sends it in a hand-built `NetrServerPasswordSet` request, since impacket has no class for opnum 6. Because it transmits only the new password's hash, opnum 6 cannot carry a password version block and the server never sees the cleartext.

**What both prove:** possession of a valid session key, which the client could only have built with the account's current secret. There is no `USER_CHANGE_PASSWORD` or `USER_FORCE_PASSWORD_CHANGE` check: the sole authorization gate is the Netlogon authenticator over the secure channel. The account changes its own secret, addressed by `AccountName`.

!!! note "Trust accounts use the flat NetBIOS name"
    `channel_type_for` maps a machine account to `WorkstationSecureChannel` and a trust to `TrustedDomainSecureChannel`. A trust authenticates only when addressed by its flat NetBIOS name plus the trailing `$` (for example `CONTOSO$`) over `TrustedDomainSecureChannel`; the DNS-name form authenticates only over `TrustedDnsDomainSecureChannel`. A mismatch returns `STATUS_NO_TRUST_SAM_ACCOUNT` from `NetrServerAuthenticate3` ([MS-NRPC] 3.5.4.4.2).

**Server-version behavior:** both are accepted over a sealed channel, including on Server 2025, which still accepts the DES OWF write here (the legacy RC4 SAMR change block does not apply to the Netlogon path). AUTO tries Netlogon AES first; for a machine account it then falls to the SAMR AES cleartext change (see the ladder above) before the Netlogon DES write, while a trust account drops straight from Netlogon AES to Netlogon DES.

## rap and rap-oem: legacy changes over SMB1 (\PIPE\LANMAN)

The Remote Administration Protocol password changes, self-service changes that ride only on SMB1 through the `\PIPE\LANMAN` gateway. They predate DCE/RPC SAMR and reach only legacy SMB1 Windows (NT 4.0 through Server 2008); modern DCs remove SMB1 and the gateway is unreachable. impacket has no RAP password support, so both requests are hand-built on impacket's raw SMB1 `SMB_COM_TRANSACTION` primitive (`rap.py`). `_connect` forces the `SMB_DIALECT` (SMB1) and raises `MethodUnavailable` when the host has no SMB1 gateway.

### rap: NetUserPasswordSet2 (opcode 115)

**Spec:** [MS-RAP] 2.5.8.1 (`NetUserPasswordSet2`, opcode 115, ParamDesc `zb16b16WW`); [MS-RAP] 3.2.5.14 and the leaked Server 2003 `xactsrv/changepw.c` for the gateway behavior.

The request packs the opcode, the ParamDesc/DataDesc descriptors, the username, two 16-byte NUL-terminated OEM password fields (old and new), and the cleartext flag and real length. Both passwords are uppercased before sending, because the legacy gateway derives the LM OWF without OEM-uppercasing the buffer itself, so an un-uppercased password fails old-password verification.

!!! danger "rap is an obsolete LM-only path and is not NTLM-usable"
    Opcode 115 derives only the LM one-way function from the cleartext passwords and calls `SamrChangePasswordUser` with `LmPresent=TRUE, NtPresent=FALSE` and no cross-encryption blobs ([MS-RAP] 3.2.5.14, leaked `user.c:8848-8858`), so it can only store the new LM hash and never the NT hash. Issued directly over `\pipe\samr` that LM-only change returns `STATUS_SUCCESS` yet leaves the NT hash unusable, so NTLM auth with the new password fails; over the RAP gateway it instead returns Win32 `0x3B` (ERROR_UNEXP_NET_ERR). Either way the result is not NTLM-usable. It is meaningful only for pure-LM accounts on a server whose `LmCompatibilityLevel` still permits LM authentication. Prefer `rap-oem` on legacy hosts.

### rap-oem: SamOEMChangePasswordUser2 (opcode 214)

**Spec:** undocumented opcode 214 (0xD6); the leaked `changepw.c` cleartext-and-OEM branch. It is the SAMR opnum-54 OEM change tunneled over `\PIPE\LANMAN` instead of `\pipe\samr`.

The request carries the ParamDesc `zsT` and DataDesc `B516B16`: a 532-byte send buffer (the 516-byte RC4 OEM password buffer plus a 16-byte verifier) rides in the SMB transaction data field, with the buffer length in 16-bit words in the parameter block. `passwolf change` builds the buffer with `crypto.build_oem_password_buffer` keyed by the old LM OWF and the verifier with `crypto.des_owf_encrypt(old_lm, new_lm)`, exactly the opnum-54 construction.

**What both prove:** knowledge of the old password as cleartext. Both derive the LM OWF from it, so neither can run pass-the-hash; `passwolf change` raises `MethodUnavailable` when only `--target-old-hash` is supplied. Like the OEM SAMR change, both reach only SMB1 hosts that still store LM hashes.

**Server-version behavior:** `rap-oem` is the working legacy RAP change (validated on Windows NT 4.0) because, unlike the cleartext `rap` (opcode 115) which is a no-op on most hosts, its RC4 OEM buffer actually completes. The two differ in what they store: `rap` (opcode 115) is LM-only and never writes the NT hash, but `rap-oem` (opcode 214) is not LM-only and does not blank NT. The server decrypts the OEM cleartext and recomputes and stores a real NT OWF (and LM OWF) from it (`SampChangePasswordUser2` -> `SampCalculateLmAndNtOwfPasswords` -> `SampStoreUserPasswords` with `NtPresent=TRUE`; [MS-SAMR] 3.1.5.10.2), so the new password is NTLM-usable. Live secretsdump on Server 2003, XP, and Server 2022 confirms the post-change NT equals `nt_owf` of the new password, not the empty-password hash. Neither reaches a modern DC, which has no SMB1 `\PIPE\LANMAN` gateway. AUTO never selects either; pin them with `--method rap` or `--method rap-oem`.

## Server 2025 summary

Windows Server 2025 enforces the CVE-2021-33757 / KB5004605 hardening by default: it refuses the legacy SAMR change opnums 38, 54, 55, and 63 with `STATUS_ACCESS_DENIED` before any password check, and accepts only the AES change, opnum 73. `passwolf change --method auto` routes around the rejection to `samr-aes`; pinning a legacy method against a 2025 DC reports the `ACCESS_DENIED` cleanly. The non-SAMR change paths (`kpasswd`, `ldap`, `netlogon-aes`, `netlogon-des`) are not opnum-gated and continue to work on Server 2025. See [methods.md](../methods.md) for the full matrix and [change.md](../guide/change.md) for selection and usage.
