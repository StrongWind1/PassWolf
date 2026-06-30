import hashlib
import hmac
import struct

from Crypto.Cipher import AES, ARC4

from passwolf import crypto
from passwolf.constants import (
    LSAD_AES256_ENC_KEY_STRING,
    SAM_AES256_ENC_KEY_STRING,
    SAM_AES256_MAC_KEY_STRING,
)


def test_nt_owf_known_vectors():
    assert crypto.nt_owf("").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert crypto.nt_owf("password").hex() == "8846f7eaee8fb117ad06bdd830b7586c"


def test_lm_owf_empty():
    assert crypto.lm_owf("").hex() == "aad3b435b51404eeaad3b435b51404ee"


def test_transform_des_key_length():
    assert len(crypto.transform_des_key(b"\x00" * 7)) == 8


def test_rc4_md5_password_buffer_roundtrips():
    session_key = b"\x33" * 16
    salt = b"\x44" * 16
    blob = crypto.build_rc4_md5_password_buffer("S3cret!pw", session_key, salt=salt)
    assert len(blob) == 532  # 516-byte encrypted buffer + 16-byte trailing salt
    cipher, trailing_salt = blob[:516], blob[516:]
    assert trailing_salt == salt
    key = hashlib.md5(salt + session_key).digest()  # noqa: S324 - spec-mandated key derivation
    plaintext = ARC4.new(key).decrypt(cipher)
    length = struct.unpack("<L", plaintext[512:516])[0]
    recovered = plaintext[512 - length : 512].decode("utf-16le")
    assert recovered == "S3cret!pw"


def test_rid_to_des_key_admin():
    # RID 500 -> little-endian f4 01 00 00; Key1 = i0 i1 i2 i3 i0 i1 i2, Key2 = i3 i0 i1 i2 i3 i0 i1.
    assert crypto.rid_to_des_key(500).hex() == "f4010000f4010000f4010000f401"


def test_pkcs7_pad_adds_full_block_when_aligned():
    padded = crypto.pkcs7_pad(b"x" * 16)
    assert len(padded) == 32
    assert padded[16:] == bytes([16]) * 16


def test_build_aes_password_buffer_layout():
    buffer = crypto.build_aes_password_buffer("AB")
    assert len(buffer) == 514
    assert buffer[:2] == (4).to_bytes(2, "little")  # "AB" is 4 UTF-16LE bytes
    assert buffer[2:6] == "AB".encode("utf-16le")  # password-first


def test_sam_aead_roundtrips_and_authenticates():
    cek = b"\x11" * 16
    iv = b"\x22" * 16
    plaintext = crypto.build_aes_password_buffer("Secret1!")
    auth_data, salt, cipher = crypto.sam_aead_encrypt(cek, plaintext, iv=iv)
    assert salt == iv

    enc_key = hmac.new(cek, SAM_AES256_ENC_KEY_STRING, hashlib.sha512).digest()[:32]
    decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(cipher)
    assert decrypted[: -decrypted[-1]] == plaintext

    mac_key = hmac.new(cek, SAM_AES256_MAC_KEY_STRING, hashlib.sha512).digest()
    expected = hmac.new(mac_key, bytes([1]) + iv + cipher + bytes([1]), hashlib.sha512).digest()
    assert auth_data == expected


def test_lsad_aead_uses_length_prefix_framing():
    cek = b"\x33" * 16
    iv = b"\x44" * 16
    value = b"trust-secret"
    _, salt, cipher = crypto.lsad_aead_encrypt(cek, value, iv=iv)
    assert salt == iv

    enc_key = hmac.new(cek, LSAD_AES256_ENC_KEY_STRING, hashlib.sha512).digest()[:32]
    decrypted = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(cipher)
    framed = decrypted[: -decrypted[-1]]
    assert struct.unpack("<L", framed[:4])[0] == len(value)
    assert framed[4:] == value


def test_des_secret_roundtrip():
    session_key = bytes(range(16))
    value = b"hello123"
    ciphertext = crypto.des_secret_encrypt(session_key, value)
    assert crypto.des_secret_decrypt(session_key, ciphertext) == value


def test_buffer_lengths():
    assert len(crypto.build_oem_password_buffer("ABC", crypto.lm_owf("old"))) == 516
    assert len(crypto.build_rc4_password_buffer("ABC", crypto.nt_owf("old"))) == 516
    assert len(crypto.build_nl_trust_password("ABC")) == 516


def test_oem_buffer_preserves_case():
    # The OEM buffer must carry the original-case password, not the uppercased form: the server recomputes
    # the NT OWF over these exact bytes, so uppercasing here would store the NT of the uppercased password
    # and break NTLM logon with the requested password (live-validated on Server 2003). Decrypt the buffer
    # and confirm the trailing bytes are the mixed-case password, not its upper() variant.
    key = crypto.lm_owf("oldpw")
    pwd = "Changed1!xQ7"
    plain = ARC4.new(key).decrypt(crypto.build_oem_password_buffer(pwd, key))
    length = int.from_bytes(plain[512:516], "little")
    assert plain[512 - length : 512] == pwd.encode("latin-1")
    assert plain[512 - length : 512] != pwd.upper().encode("latin-1")


def test_pbkdf2_sam_cek_length():
    assert len(crypto.pbkdf2_sam_cek(crypto.nt_owf("old"), b"\x00" * 16, 5000)) == 16
