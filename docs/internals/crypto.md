# Crypto and password buffers

This page is the reference for the cryptography and the wire structures that carry passwords in passwolf. Everything described here is implemented in `src/passwolf/crypto.py` and the NDR types it feeds in `src/passwolf/ndr.py`. The change and reset methods that select among these constructions are documented in [change-methods.md](change-methods.md) and [reset-methods.md](reset-methods.md); the SMB session key that several of them depend on comes from the transport, covered in [transport.md](transport.md).

Every password write in this protocol set uses exactly one of four cipher constructions. The rest of the page is organized so you can read each method's choice against this list.

| Construction | Spec | Used by |
|---|---|---|
| DES-ECB per 8-byte block, 7-byte key (OWF encryption) | [MS-SAMR] 2.2.11.1.1 and 2.2.11.1.2 | the 16-byte hash verifiers in the legacy change methods, and the set-hash reset |
| RC4 over the 516-byte buffer, keyed by an OWF | [MS-SAMR] 3.2.2.1 | `samr-rc4`, `samr-oem`, `samr-diag` change |
| RC4 over the 532-byte buffer, keyed by MD5(salt + session key) | [MS-SAMR] 3.2.2.2 | the salted RC4 reset (`UserInternal4InformationNew`, level 25; `UserInternal5InformationNew`, level 26, is the spec alias the server maps to 25 but passwolf does not emit) |
| AEAD-AES-256-CBC-HMAC-SHA512 | [MS-SAMR] 3.2.2.4, 3.2.2.5, 2.2.1.18 | `samr-aes` change (opnum 73); `samr-aes` reset (`UserInternal7`) and `--reset-info-class internal8` reset (`UserInternal8`) |

!!! note "One request can mix two ciphers"
    The DES-verifier and RC4-buffer split is per request, not per method. A single `SamrUnicodeChangePasswordUser2` PDU carries an RC4-encrypted password buffer and a DES-encrypted NT-hash verifier at the same time. Do not assume one cipher for the whole message. See [MS-SAMR] 2.2.6.21 and 2.2.11.1.1.

## Shared primitives

### NTOWFv1 and LMOWFv1

The one-way functions that produce the 16-byte hashes are defined in [MS-NLMP] 3.3.1.

- NTOWFv1 is MD4 of the UTF-16LE password. In `crypto.py` this is `nt_owf(password)`, returning `MD4.new(password.encode("utf-16le")).digest()`.
- LMOWFv1 uppercases the password, encodes it as OEM (latin-1) truncated and padded to 14 bytes, splits that into two 7-byte DES keys, and DES-encrypts the fixed magic string `KGS!@#$%` under each. In `crypto.py` this is `lm_owf(password)`; the magic constant is `LM_MAGIC = b"KGS!@#$%"`.

These OWFs are the keying material for the legacy methods: the NT OWF keys the Unicode RC4 change, the LM OWF keys the OEM RC4 change, and the NT OWF feeds the PBKDF2 derivation on the AES change path.

### The DES key transform ([MS-SAMR] 2.2.11.1.2)

DES keys in this protocol are stored as 7 bytes and expanded to 8 bytes by inserting a parity bit after every seventh bit. The low bit of each output byte is a parity bit. The spec's step 4 ([MS-SAMR] 2.2.11.1.2) sets it to odd parity, but DES ignores parity bits during key scheduling, so passwolf implements steps 1-3 and intentionally skips the step-4 parity computation, leaving the LSB zero. This is `transform_des_key(key7)` in `crypto.py`. The bit math below implements steps 1-3; it does not set the odd-parity bit:

```python
out = bytes([
    k[0] >> 1,
    ((k[0] & 0x01) << 6) | (k[1] >> 2),
    ((k[1] & 0x03) << 5) | (k[2] >> 3),
    ((k[2] & 0x07) << 4) | (k[3] >> 4),
    ((k[3] & 0x0F) << 3) | (k[4] >> 5),
    ((k[4] & 0x1F) << 2) | (k[5] >> 6),
    ((k[5] & 0x3F) << 1) | (k[6] >> 7),
    k[6] & 0x7F,
])
return bytes((b << 1) & 0xFF for b in out)
```

The normative test vector in [MS-SAMR] 4.3 expands 7-byte input `25 67 81 a6 20 31 28` to 8-byte odd-parity output `25 b3 e0 34 62 01 c4 51`. `transform_des_key` zeroes the parity LSB instead of setting it for odd parity, so its output for that input is `24 b2 e0 34 62 00 c4 50` - identical except in the low bit of each byte. Since DES ignores the parity bit during key scheduling, the resulting DES key is functionally equivalent to the spec's. The suite's `test_transform_des_key_length` only checks the output length (8 bytes); it does not perform a byte-for-byte known-answer comparison against the 4.3 vector.

### DES OWF encryption ([MS-SAMR] 2.2.11.1.1)

"Encrypting an NT or LM hash value with a specified key" splits the 16-byte hash into Block1 (bytes 0..7) and Block2 (bytes 8..15) and DES-ECB encrypts each block under its own 7-byte key. For a 16-byte key the two halves are `key[0..6]` and `key[7..13]`; bytes 14 and 15 are discarded ([MS-SAMR] 2.2.11.1.4). This is `des_owf_encrypt(data16, key)` in `crypto.py`:

```python
k1 = transform_des_key(key[:7])
k2 = transform_des_key(key[7:14])
left = DES.new(k1, DES.MODE_ECB).encrypt(data16[:8])
right = DES.new(k2, DES.MODE_ECB).encrypt(data16[8:])
return left + right
```

For the DSRM reset the key is derived from the account RID rather than from a hash, per [MS-SAMR] 2.2.11.1.3; that derivation is `rid_to_des_key(rid)` in `crypto.py`.

!!! info "This is DES, not RC4"
    The 16-byte hash verifiers carried in the legacy change methods (the `Old*OwfPasswordEncryptedWithNew*` fields, and the set-hash reset payload) are DES-encrypted by `des_owf_encrypt`. The cleartext password buffer in the same request is RC4-encrypted by `build_rc4_password_buffer`. Both halves of one change PDU use different ciphers.

## Cleartext password buffers

### SAMPR_USER_PASSWORD: 516 bytes ([MS-SAMR] 2.2.6.21)

The legacy cleartext layout. The decrypted form `SAMPR_USER_PASSWORD` is a 512-byte buffer (256 WCHAR) followed by a 4-byte little-endian length. The password is right-justified: the UTF-16LE bytes sit at the END of the 512-byte field with the leading bytes random fill, and `Length` records how many bytes of password are at the tail. The encrypted form `SAMPR_ENCRYPTED_USER_PASSWORD` is the RC4 image of all 516 bytes.

| Field | Size | Meaning |
|---|---|---|
| Buffer | 512 bytes (256 WCHAR) | random fill, then the right-justified UTF-16LE password |
| Length | 4 bytes, little-endian | password byte count at the tail of Buffer |
| (encrypted) | 516 bytes | RC4 image of Buffer + Length |

passwolf builds this in `build_rc4_password_buffer(password, rc4_key)`: `os.urandom(512 - len(enc)) + enc` then a packed `<L` length, RC4-encrypted under `rc4_key`. Unlike impacket, which pads with the literal byte `0x41` ('A'), passwolf uses random fill, which is what the spec calls for. The OEM variant `build_oem_password_buffer` is the same layout but uppercases and OEM-encodes the password first, for `SamrOemChangePasswordUser2`.

### SAMPR_USER_PASSWORD_NEW: 532 bytes with a 16-byte salt ([MS-SAMR] 2.2.6.22)

The salted variant adds a trailing 16-byte clear salt. The buffer is 532 bytes, but only the first 516 are RC4-encrypted; the last 16 bytes (the salt) travel in the clear so the server can re-derive the RC4 key.

| Field | Size | Meaning |
|---|---|---|
| Buffer | 512 bytes | random fill, then the right-justified UTF-16LE password |
| Length | 4 bytes, little-endian | password byte count |
| ClearSalt | 16 bytes | random salt, NOT encrypted; feeds the MD5 key derivation in 3.2.2.2 |

passwolf builds this in `build_rc4_md5_password_buffer(password, session_key, salt)`. It RC4-encrypts the 516-byte cleartext under `MD5(salt + session_key)` and appends the 16-byte salt: `ARC4.new(key).encrypt(plaintext) + nonce`. This is the buffer for the RC4 salted reset info levels.

### SAMPR_USER_PASSWORD_AES: length-prefixed plaintext ([MS-SAMR] 2.2.6.32)

The AES-era plaintext is shaped differently from the legacy buffers. It is length-prefixed, not right-justified: a 2-byte little-endian `PasswordLength` comes first, then the password at the START of the 512-byte buffer with random fill after it.

| Field | Size | Meaning |
|---|---|---|
| PasswordLength | 2 bytes, little-endian | UTF-16LE password byte count |
| Buffer | 512 bytes | the UTF-16LE password first (password-first), then random fill |

passwolf builds the 514-byte plaintext in `build_aes_password_buffer(password)`: `struct.pack("<H", len(pwd)) + pwd + os.urandom(512 - len(pwd))`. This plaintext is what the AEAD construction below encrypts.

## Encrypted wire structures

### SAMPR_ENCRYPTED_USER_PASSWORD and _NEW

The encrypted forms of the two legacy cleartext buffers are opaque byte arrays. `SAMPR_ENCRYPTED_USER_PASSWORD` is 516 bytes ([MS-SAMR] 2.2.6.21); `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` is 532 bytes ([MS-SAMR] 2.2.6.22). passwolf reuses impacket's NDR classes for these two, since impacket models them correctly.

### SAMPR_ENCRYPTED_PASSWORD_AES ([MS-SAMR] 2.2.6.32)

The AES wrapper. impacket does not model this struct, so passwolf defines it in `ndr.py`.

```
typedef struct _SAMPR_ENCRYPTED_PASSWORD_AES {
  UCHAR     AuthData[64];      ; HMAC-SHA-512 tag
  UCHAR     Salt[16];          ; nonce reused as PBKDF2 salt, AES-CBC IV, and transmitted Salt
  ULONG     cbCipher;          ; length of Cipher
  PUCHAR    Cipher;            ; AES-CBC ciphertext, [size_is(cbCipher)]
  ULONGLONG PBKDF2Iterations;  ; iteration count chosen by the client
} SAMPR_ENCRYPTED_PASSWORD_AES;
```

| Field | Size | Meaning |
|---|---|---|
| AuthData | 64 bytes | full HMAC-SHA-512 tag over versionbyte + IV + Cipher + versionbyte_length |
| Salt | 16 bytes | one random nonce reused three ways: the PBKDF2 salt, the AES-CBC IV, and this transmitted field |
| cbCipher | 4 bytes | length of Cipher in bytes |
| Cipher | cbCipher bytes | raw AES-CBC ciphertext only; the IV is NOT prepended, it is recovered from Salt |
| PBKDF2Iterations | 8 bytes | required and used by the server for opnum 73 (in [5000, 1000000]); ignored on the session-key reset path |

The `ndr.py` class forces 8-byte alignment because of the trailing `ULONGLONG`. The same shape, minus `PBKDF2Iterations`, is the LSA secret type `LSAPR_AES_CIPHER_VALUE` used by `LsarSetSecret2`.

!!! warning "The IV is not a separate field"
    There is no IV member in the struct. One random 16-byte nonce per encryption serves as the PBKDF2 salt, the AES-CBC IV, and the transmitted `Salt[16]`. The server reads `Salt` and uses it as the IV. passwolf's `_aead_encrypt` takes a single `iv` argument and returns it as the value placed in `Salt`.

### ENCRYPTED_NT_OWF_PASSWORD and ENCRYPTED_LM_OWF_PASSWORD ([MS-SAMR] 2.2.7.3)

16 bytes of opaque data holding a DES-encrypted NT or LM hash (two 8-byte DES blocks per 2.2.11.1.1). The two typedefs are identical; the name documents which hash the bytes carry. These are the verifier and set-hash payloads, produced by `des_owf_encrypt`. passwolf reuses impacket's classes, which are correct.

## Key derivation and cipher usage

### RC4 over the password buffer ([MS-SAMR] 3.2.2.1)

Plain RC4 over the 516-byte buffer. The 16-byte RC4 key is method-specific:

- `samr-oem` change (`SamrOemChangePasswordUser2`, opnum 54): key is the LM OWF of the existing password.
- `samr-rc4` change (`SamrUnicodeChangePasswordUser2`, opnum 55): key is the NT OWF of the existing password.

The `samr-rc4` reset does not use this plain path; it sends the salted `UserInternal4InformationNew` buffer keyed by `MD5(salt + session key)`, described in the next section.

For the change methods the key is an OWF of the OLD password, so the old NT or LM hash alone is sufficient to build the request. That is why passwolf change accepts `--target-old-hash`: a pass-the-hash change runs from the old NT hash alone on every method that keys only on it, the SAMR `samr-rc4`, `samr-aes`, `samr-des`, and `samr-diag` changes and the Netlogon machine/trust changes, while `samr-oem`, `kpasswd`, `ldap`, and the RAP changes still need the cleartext old password.

### RC4 keyed by MD5(salt + session key) ([MS-SAMR] 3.2.2.2)

The salted reset variant, used by the `samr-rc4` reset (`SamrSetInformationUser2` with `UserInternal4InformationNew`, info level 25). The 16-byte RC4 key is `MD5(ClearSalt || user-session-key)`, where the session key is the 16-byte SMB session key (3.2.2.3) and `ClearSalt` is the random salt that travels in the clear at the tail of the buffer. Only the first 516 bytes are RC4-encrypted; the trailing 16-byte salt is not. The salt defeats key reuse when one session key encrypts multiple password sets.

### The SMB session key as content-encryption key ([MS-SAMR] 3.2.2.3)

Several keys above are "the 16-byte SMB session key." The spec sources it from [MS-CIFS] 3.4.4.6: it is the session key of the authenticated SMB/RPC transport carrying the SAMR call. The same value both protects the transport (SMB3 encryption rides over it) and keys the SAMR password buffers on the session-key reset paths. passwolf pulls it from the SMB connection; how the connection is established is covered in [transport.md](transport.md).

### AEAD-AES-256-CBC-HMAC-SHA512 ([MS-SAMR] 3.2.2.4, 2.2.1.18)

The AES-era construction. From a content-encryption key (CEK), encryption derives two subkeys, runs AES-256-CBC over the plaintext under a random 16-byte IV, and authenticates with HMAC-SHA-512. In `crypto.py` this is `_aead_encrypt`, called via `sam_aead_encrypt`:

```python
enc_key  = hmac.new(cek, enc_label, hashlib.sha512).digest()[:32]   # truncated to 32 bytes
mac_key  = hmac.new(cek, mac_label, hashlib.sha512).digest()        # full 64 bytes
cipher   = AES.new(enc_key, AES.MODE_CBC, nonce).encrypt(pkcs7_pad(plaintext))
mac_in   = bytes([0x01]) + nonce + cipher + bytes([0x01])
auth_data = hmac.new(mac_key, mac_in, hashlib.sha512).digest()
```

The two derivation labels are NUL-terminated ANSI strings from [MS-SAMR] 2.2.1.18, kept in `constants.py`:

| Constant | Value (NUL appended) | Length with NUL |
|---|---|---|
| SAM_AES256_ENC_KEY_STRING | `Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16` | 61 |
| SAM_AES256_MAC_KEY_STRING | `Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16` | 54 |

The version framing byte is `0x01` (`AEAD_VERSION_BYTE` in `constants.py`), used both as the leading byte and as the trailing versionbyte_length in the MAC pre-image. The CEK is method-specific:

=== "samr-aes reset (UserInternal7 / UserInternal8)"

    `SamrSetInformationUser2` (opnum 58, the identical sibling of `SamrSetInformationUser` opnum 37) with `UserInternal7Information` (info level 31) or `UserInternal8Information` (info level 32). The shared secret and the CEK are both the 16-byte SMB session key. `PBKDF2Iterations` is ignored on this path; passwolf sets it to 0. `UserInternal8` wraps the full `SAMPR_USER_ALL_INFORMATION` block alongside the encrypted password, which is why passwolf reset exposes it through the separate `--reset-info-class internal8` flag. The opnum 37 / opnum 58 equivalence is the anchor at [reset-methods.md](reset-methods.md).

=== "samr-aes change (opnum 73)"

    `SamrUnicodeChangePasswordUser4`, opnum 73. The shared secret is the plaintext old password; the CEK is derived by PBKDF2 (below). Like opnums 54 and 55, this change requires no SAM context handle (only opnum 38 is handle-bound), so it can be sent directly to the server even when the DC rejects the legacy DES/RC4 changes (opnums 38/54/55) under the CVE-2021-33757 hardening. What is unique to opnum 73 is the AES cipher and that it is the sole change the Server 2025 hardening still accepts.

### PBKDF2 key derivation from the plaintext password ([MS-SAMR] 3.2.2.5)

For the AES change (opnum 73) the CEK is derived from the old password rather than from a session key, so a handle-less caller can still produce it. passwolf computes it in `pbkdf2_sam_cek`:

```python
return hashlib.pbkdf2_hmac("sha512", nt_hash, salt, iterations, dklen=16)
```

The input is the NT OWF of the old password (derivable from a hash, so `--target-old-hash` works here too), the salt is the 16-byte `SAMPR_ENCRYPTED_PASSWORD_AES.Salt`, and the output is the 16-byte CEK. The iteration count MUST be in [5000, 1000000] inclusive; the server re-derives the CEK with the transmitted `PBKDF2Iterations` and rejects out-of-range values per [MS-SAMR] 3.1.5.10.4. passwolf's bounds and default live in `constants.py` as `PBKDF2_ITERATIONS_MIN`, `PBKDF2_ITERATIONS_MAX`, and `PBKDF2_ITERATIONS_DEFAULT` (10000).

!!! danger "Why AES matters on current DCs"
    Windows Server 2025 with the CVE-2021-33757 / KB5004605 hardening rejects the legacy change methods (opnums 38, 54, 55) with STATUS_ACCESS_DENIED (0xC0000022) before any password check, leaving opnum 73 as the only accepted SAMR change. impacket implements none of the AES path, so it cannot perform a SAMR change there (its non-SAMR LDAP and kpasswd changes are not gated and still work). passwolf's `samr-aes` change is the SAMR method that still works; AUTO selects it ahead of the RC4 changes. See [change-methods.md](change-methods.md).

## Method-to-buffer mapping

The table below names the buffer struct and key for each method as the CLI exposes it. The exact method tokens come from `passwolf change --method` and `passwolf reset --method`.

| Tool and method | Opnum / info level | Buffer struct | Key |
|---|---|---|---|
| passwolf change `samr-des` | opnum 38 | `ENCRYPTED_NT/LM_OWF_PASSWORD` cross-encryption pairs | DES OWF (each hash keyed by the other new/old OWF; no session key) |
| passwolf change `samr-oem` | opnum 54 | `SAMPR_ENCRYPTED_USER_PASSWORD` (516) + DES verifier | RC4 by old LM OWF; verifier DES |
| passwolf change `samr-rc4` | opnum 55 | `SAMPR_ENCRYPTED_USER_PASSWORD` (516) + DES verifier | RC4 by old NT OWF; verifier DES |
| passwolf change `samr-diag` | opnum 63 | same as opnum 55 plus AdditionalData | RC4 by old NT OWF; verifier DES |
| passwolf change `samr-aes` | opnum 73 | `SAMPR_ENCRYPTED_PASSWORD_AES` (AES) | AEAD-AES, CEK = PBKDF2(old NT hash) |
| passwolf change `netlogon-des` | NRPC opnum 6 | `ENCRYPTED_NT_OWF_PASSWORD` (16) | DES OWF, secure-channel key |
| passwolf reset `samr-rc4` | info 25 (`UserInternal4InformationNew`, salted) | `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` (532) | RC4 by MD5(salt + session key) |
| passwolf reset `samr-aes` | info 31 (`UserInternal7`) | `SAMPR_ENCRYPTED_PASSWORD_AES` | AEAD-AES, CEK = session key |
| passwolf reset `--reset-info-class internal8` | info 32 (`UserInternal8`) | `SAMPR_ENCRYPTED_PASSWORD_AES` + all-info | AEAD-AES, CEK = session key |
| passwolf reset `samr-hash` | info 18 (`UserInternal1`) | `ENCRYPTED_NT_OWF_PASSWORD` (16) | DES OWF, session key |

Every SAMR reset row above is carried over opnum 58 (`SamrSetInformationUser2`) except `samr-hash`, which passwolf sends over opnum 37 (`SamrSetInformationUser`); the two opnums are interchangeable ([MS-SAMR] 3.1.5.6.5: opnum 37 "MUST behave as with a call to SamrSetInformationUser2"), so the info class, not the opnum, selects the operation. The raw NT/LM OWF can be set over either opnum by two info classes: `UserInternal1` (level 18, the dedicated hash class `samr-hash` uses) and `UserAllInformation` (level 21, which can also carry the OWF fields); both were live-confirmed to set the NT hash on Server 2022 and 2025. See [reset-methods.md](reset-methods.md) for the equivalence.

The `kpasswd`, `ldap`, and `rap` methods do not use these SAMR buffers: they carry the cleartext password inside an already-encrypted channel (Kerberos AP exchange, sealed LDAP, or an authenticated RAP call). For the full per-method walk-through see [change-methods.md](change-methods.md) and [reset-methods.md](reset-methods.md); for the channels that carry them, see [transport.md](transport.md).
