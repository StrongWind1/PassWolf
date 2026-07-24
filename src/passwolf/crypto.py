# SPDX-License-Identifier: Apache-2.0
"""Password cryptography for the change and reset wire formats.

Everything impacket gets right (the DES OWF transform) is reimplemented here too, deliberately, so the
module is self-contained and covered by known-answer tests rather than trusting a third party for the
load-bearing AES paths impacket does not implement at all. Each construction cites its spec section.

Spec mapping:
  - [MS-SAMR] 2.2.11.1.x  DES key transform and OWF encryption.
  - [MS-SAMR] 2.2.1.18 / 3.2.2.4  AEAD-AES-256-CBC-HMAC-SHA512 (SAM password buffers).
  - [MS-SAMR] 3.2.2.5  PBKDF2 content-encryption key from the old NT hash.
  - [MS-SAMR] 3.2.2.1  RC4 SAMPR_USER_PASSWORD buffer.
  - [MS-LSAD] 2.2.1.4 / 5.1.5  AEAD-AES-256-CBC-HMAC-SHA512 (LSA secret store).
  - [MS-LSAD] 5.1.2  DES advancing-key secret encryption.
  - [MS-NRPC] 3.4.5  AES-128-CFB8 NL_TRUST_PASSWORD buffer.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import MD4

from .constants import (
    AEAD_VERSION_BYTE,
    LSAD_AES256_ENC_KEY_STRING,
    LSAD_AES256_MAC_KEY_STRING,
    NL_TRUST_PASSWORD_BUFFER_BYTES,
    PASSWORD_BUFFER_BYTES,
    SAM_AES256_ENC_KEY_STRING,
    SAM_AES256_MAC_KEY_STRING,
)

LM_MAGIC = b"KGS!@#$%"  # [MS-NLMP] 3.3.1 LMOWFv1 fixed plaintext
DES_KEY_BYTES = 7
AES_BLOCK_BYTES = 16


# --- DES OWF primitives ([MS-SAMR] 2.2.11.1.x, [MS-NLMP] 3.3.1) ---
def transform_des_key(key7: bytes) -> bytes:
    """Expand a 7-byte key into an 8-byte DES key by inserting a parity bit after every 7 bits.

    This is the string-to-key transform shared by LM OWF and the SAM OWF encryption. The low bit of
    each output byte is parity and is ignored by DES, so it is left zero.
    """
    if len(key7) != DES_KEY_BYTES:
        msg = "DES key transform input must be 7 bytes"
        raise ValueError(msg)
    k = key7
    out = bytes(
        [
            k[0] >> 1,
            ((k[0] & 0x01) << 6) | (k[1] >> 2),
            ((k[1] & 0x03) << 5) | (k[2] >> 3),
            ((k[2] & 0x07) << 4) | (k[3] >> 4),
            ((k[3] & 0x0F) << 3) | (k[4] >> 5),
            ((k[4] & 0x1F) << 2) | (k[5] >> 6),
            ((k[5] & 0x3F) << 1) | (k[6] >> 7),
            k[6] & 0x7F,
        ],
    )
    return bytes((b << 1) & 0xFF for b in out)


def des_owf_encrypt(data16: bytes, key: bytes) -> bytes:
    """Encrypt a 16-byte OWF with a two-half DES key (impacket SamEncryptNTLMHash, by hand).

    The first 14 bytes of ``key`` form two 7-byte DES key halves; each 8-byte half of ``data16`` is
    DES-ECB encrypted under the matching half. Used for the set-hash reset, DSRM, and Netlogon opnum 6.
    """
    if len(data16) != AES_BLOCK_BYTES:
        msg = "DES OWF input must be 16 bytes"
        raise ValueError(msg)
    k1 = transform_des_key(key[:DES_KEY_BYTES])
    k2 = transform_des_key(key[DES_KEY_BYTES : DES_KEY_BYTES * 2])
    left = DES.new(k1, DES.MODE_ECB).encrypt(data16[:8])
    right = DES.new(k2, DES.MODE_ECB).encrypt(data16[8:])
    return left + right


def nt_owf(password: str) -> bytes:
    """NTOWFv1: MD4 of the UTF-16LE password ([MS-NLMP] 3.3.1)."""
    return MD4.new(password.encode("utf-16le")).digest()


def lm_owf(password: str) -> bytes:
    """LMOWFv1: DES of the fixed magic under the uppercased, 14-byte OEM password ([MS-NLMP] 3.3.1)."""
    pw = password.upper().encode("latin-1", "replace")[:14].ljust(14, b"\x00")
    k1 = transform_des_key(pw[:DES_KEY_BYTES])
    k2 = transform_des_key(pw[DES_KEY_BYTES:])
    return DES.new(k1, DES.MODE_ECB).encrypt(LM_MAGIC) + DES.new(k2, DES.MODE_ECB).encrypt(LM_MAGIC)


def rid_to_des_key(rid: int) -> bytes:
    """Build the 14-byte DES key for SamrSetDSRMPassword from a RID ([MS-SAMR] 2.2.11.1.3)."""
    i = rid.to_bytes(4, "little")
    key1 = bytes([i[0], i[1], i[2], i[3], i[0], i[1], i[2]])
    key2 = bytes([i[3], i[0], i[1], i[2], i[3], i[0], i[1]])
    return key1 + key2


# --- PKCS#7 ---
def pkcs7_pad(data: bytes, block: int = AES_BLOCK_BYTES) -> bytes:
    """PKCS#7 pad to a block boundary; a full padding block is added when already aligned."""
    n = block - (len(data) % block)
    return data + bytes([n]) * n


# --- PBKDF2 content-encryption key ([MS-SAMR] 3.2.2.5) ---
def pbkdf2_sam_cek(nt_hash: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive the 16-byte CEK for the AES change from the account NT hash via PBKDF2-HMAC-SHA512."""
    return hashlib.pbkdf2_hmac("sha512", nt_hash, salt, iterations, dklen=16)


# --- AEAD-AES-256-CBC-HMAC-SHA512 ([MS-SAMR] 3.2.2.4, [MS-LSAD] 5.1.5) ---
def _aead_encrypt(cek: bytes, plaintext: bytes, enc_label: bytes, mac_label: bytes, iv: bytes | None) -> tuple[bytes, bytes, bytes]:
    """Encrypt a pre-built plaintext and return (auth_data, iv, cipher).

    The single random 16-byte ``iv`` is the AES-CBC IV and is carried on the wire as the Salt field; it
    is also the PBKDF2 salt on the SAM change path. The authentication tag is HMAC-SHA512 over
    versionbyte + iv + cipher + versionbyte_length, both framing bytes being 0x01.
    """
    nonce = os.urandom(AES_BLOCK_BYTES) if iv is None else iv
    enc_key = hmac.new(cek, enc_label, hashlib.sha512).digest()[:32]
    mac_key = hmac.new(cek, mac_label, hashlib.sha512).digest()
    cipher = AES.new(enc_key, AES.MODE_CBC, nonce).encrypt(pkcs7_pad(plaintext))
    mac_input = bytes([AEAD_VERSION_BYTE]) + nonce + cipher + bytes([AEAD_VERSION_BYTE])
    auth_data = hmac.new(mac_key, mac_input, hashlib.sha512).digest()
    return auth_data, nonce, cipher


def sam_aead_encrypt(cek: bytes, plaintext_buffer: bytes, iv: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """AEAD encrypt a SAMPR_USER_PASSWORD_AES buffer for SAMR opnum 73 or UserInternal7/8."""
    return _aead_encrypt(cek, plaintext_buffer, SAM_AES256_ENC_KEY_STRING, SAM_AES256_MAC_KEY_STRING, iv)


def lsad_aead_encrypt(cek: bytes, value: bytes, iv: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """AEAD encrypt an LSA secret value for LsarSetSecret2 (opnum 138).

    The AES (5.1.5) plaintext is a single ULONG length prefix followed by the value, then PKCS#7
    padded. Unlike the DES 5.1.2 path it carries no version field; the version lives in the AEAD
    framing byte. This framing was recovered live and has no reference implementation in impacket.
    """
    framed = struct.pack("<L", len(value)) + value
    return _aead_encrypt(cek, framed, LSAD_AES256_ENC_KEY_STRING, LSAD_AES256_MAC_KEY_STRING, iv)


# --- SAMPR_USER_PASSWORD_AES plaintext ([MS-SAMR] 2.2.6.32) ---
def build_aes_password_buffer(password: str) -> bytes:
    """Build the 514-byte SAMPR_USER_PASSWORD_AES plaintext: LE16 length, then the password first.

    The UTF-16LE password sits at the START of the 512-byte buffer (password-first), the remainder is
    random fill. This is the opposite of the legacy RC4 buffer, which right-aligns the password.
    """
    pwd = password.encode("utf-16le")
    if len(pwd) > PASSWORD_BUFFER_BYTES:
        msg = "password exceeds the 256-character SAMPR_USER_PASSWORD_AES limit"
        raise ValueError(msg)
    buffer = pwd + os.urandom(PASSWORD_BUFFER_BYTES - len(pwd))
    return struct.pack("<H", len(pwd)) + buffer


# --- RC4 SAMPR_USER_PASSWORD buffer ([MS-SAMR] 3.2.2.1) ---
def build_rc4_password_buffer(password: str, rc4_key: bytes) -> bytes:
    """Build the 516-byte RC4-encrypted SAMPR_USER_PASSWORD buffer (right-aligned password + length).

    The 512-byte buffer holds random fill then the right-justified UTF-16LE password; a trailing ULONG
    carries the password byte length. Used by the diagnostic Unicode change (opnum 63, ``change_diag``)
    and the unsalted RC4 cleartext resets (``UserInternal4`` / ``UserInternal5``). The plain RC4 change
    (opnum 55) goes through impacket's own helper, and the OEM change (opnum 54) uses the latin-1
    ``build_oem_password_buffer`` instead, so neither calls this builder.
    """
    enc = password.encode("utf-16le")
    if len(enc) > PASSWORD_BUFFER_BYTES:
        msg = "password exceeds the 256-character SAMPR_USER_PASSWORD limit"
        raise ValueError(msg)
    buffer = os.urandom(PASSWORD_BUFFER_BYTES - len(enc)) + enc
    plaintext = buffer + struct.pack("<L", len(enc))
    return ARC4.new(rc4_key).encrypt(plaintext)


def build_rc4_md5_password_buffer(password: str, session_key: bytes, salt: bytes | None = None) -> bytes:
    """Build the 532-byte SAMPR_ENCRYPTED_USER_PASSWORD_NEW buffer for the RC4 cleartext reset.

    The 512-byte buffer holds random fill then the right-justified UTF-16LE password and a trailing ULONG
    length; it is RC4-encrypted under MD5(salt + session_key) and the 16-byte salt is appended on the
    wire so the server can re-derive the key. Per [MS-SAMR] 3.2.2.2 (UserInternal4InformationNew).
    """
    nonce = os.urandom(AES_BLOCK_BYTES) if salt is None else salt
    enc = password.encode("utf-16le")
    if len(enc) > PASSWORD_BUFFER_BYTES:
        msg = "password exceeds the 256-character SAMPR_USER_PASSWORD limit"
        raise ValueError(msg)
    buffer = os.urandom(PASSWORD_BUFFER_BYTES - len(enc)) + enc
    plaintext = buffer + struct.pack("<L", len(enc))
    key = hashlib.md5(nonce + session_key).digest()
    return ARC4.new(key).encrypt(plaintext) + nonce


def build_oem_password_buffer(password: str, rc4_key: bytes) -> bytes:
    """Build the 516-byte RC4-encrypted OEM SAMPR_USER_PASSWORD buffer for SamrOemChangePasswordUser2.

    The original-case ANSI password is right-justified in the 512-byte buffer with a trailing ULONG
    length, RC4 keyed by the old LM OWF hash. Case is preserved deliberately: the server decodes the OEM
    bytes verbatim and recomputes BOTH the NT OWF (over the exact bytes, [MS-SAMR] 3.1.5.10.2 step 9 ->
    SampCalculateLmAndNtOwfPasswords) and the LM OWF (uppercasing internally) from them, so uppercasing
    here would silently store the NT of the uppercased text and break NTLM logon with the requested
    password. The canonical Windows client (toempass.c) likewise upcases only the LM-OWF verifier key,
    never the buffer. Live-validated on Server 2003: a mixed-case new password yields nt_owf(mixed-case)
    and logs in, whereas the previous .upper() yielded nt_owf(UPPER) only.
    """
    pwd = password.encode("latin-1", "replace")
    if len(pwd) > PASSWORD_BUFFER_BYTES:
        msg = "password exceeds the SAMPR_USER_PASSWORD OEM buffer limit"
        raise ValueError(msg)
    buffer = os.urandom(PASSWORD_BUFFER_BYTES - len(pwd)) + pwd
    plaintext = buffer + struct.pack("<L", len(pwd))
    return ARC4.new(rc4_key).encrypt(plaintext)


# --- Netlogon NL_TRUST_PASSWORD buffer ([MS-NRPC] 2.2.1.3.7, 3.4.5.2.6) ---
def build_nl_trust_password(password: str) -> bytes:
    """Build the 516-byte NL_TRUST_PASSWORD plaintext: random fill, right-aligned password, length."""
    pw = password.encode("utf-16le")
    if len(pw) > NL_TRUST_PASSWORD_BUFFER_BYTES:
        msg = "password exceeds the NL_TRUST_PASSWORD buffer limit"
        raise ValueError(msg)
    buffer = os.urandom(NL_TRUST_PASSWORD_BUFFER_BYTES - len(pw)) + pw
    return buffer + struct.pack("<L", len(pw))


def aes_cfb8_encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """AES-128-CFB8 with a zero IV under the secure-channel session key (Netlogon opnum 30)."""
    return AES.new(session_key, AES.MODE_CFB, b"\x00" * AES_BLOCK_BYTES, segment_size=8).encrypt(plaintext)


# --- LSA secret DES advancing-key cipher ([MS-LSAD] 5.1.2) ---
def _advance_key(key: bytes, idx: int) -> bytes:
    """Return the 7-byte advancing key slice at position idx, wrapping over the session key."""
    return bytes(key[(idx + j) % len(key)] for j in range(DES_KEY_BYTES))


def des_secret_encrypt(session_key: bytes, value: bytes) -> bytes:
    """Encrypt an LSA secret value with the DES 5.1.2 advancing-key construction.

    The plaintext is a ULONG length and a ULONG version (1) header followed by the value, zero-padded
    to an 8-byte boundary; each 8-byte block uses a fresh DES key from the advancing 7-byte slice.
    """
    framed = struct.pack("<LL", len(value), 1) + value
    if len(framed) % 8:
        framed += b"\x00" * (8 - len(framed) % 8)
    out = b""
    idx = 0
    for i in range(0, len(framed), 8):
        key = transform_des_key(_advance_key(session_key, idx))
        out += DES.new(key, DES.MODE_ECB).encrypt(framed[i : i + 8])
        idx = (idx + DES_KEY_BYTES) % len(session_key)
    return out


def des_secret_decrypt(session_key: bytes, ciphertext: bytes) -> bytes:
    """Invert :func:`des_secret_encrypt`, returning the secret value without its length/version header."""
    out = b""
    idx = 0
    for i in range(0, len(ciphertext), 8):
        key = transform_des_key(_advance_key(session_key, idx))
        out += DES.new(key, DES.MODE_ECB).decrypt(ciphertext[i : i + 8])
        idx = (idx + DES_KEY_BYTES) % len(session_key)
    length = struct.unpack("<L", out[:4])[0]
    return out[8 : 8 + length]
