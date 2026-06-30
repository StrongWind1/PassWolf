"""LSA trust-secret set: LsarSetSecret2 (opnum 138, AES) and LsarSetSecret (opnum 29, DES).

A trust password is stored as an LSA secret, so rotating it is a privileged write of a secret value.
This is the reset-class counterpart for trust accounts. The AES container and a clean DES cipher are
both built here because impacket's LsarSetSecret helper is broken and it has no opnum-138 class at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL
from impacket.dcerpc.v5.lsad import MSRPC_UUID_LSAD
from impacket.dcerpc.v5.rpcrt import DCERPCException

from . import crypto, ndr
from .errors import MethodUnavailable
from .nterror import STATUS_SUCCESS

if TYPE_CHECKING:
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5

LSA_PIPE = r"\lsarpc"
LSA_UUID = MSRPC_UUID_LSAD


def open_secret(dce: DCERPC_v5, name: str, *, create: bool) -> object:
    """Open (or create) a named LSA secret and return its handle."""
    policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]
    if create:
        return lsad.hLsarCreateSecret(dce, policy, name, MAXIMUM_ALLOWED)["SecretHandle"]
    return lsad.hLsarOpenSecret(dce, policy, name, MAXIMUM_ALLOWED)["SecretHandle"]


def _request_status(dce: DCERPC_v5, request: object) -> int:
    """Send an LSA write and return STATUS_SUCCESS, mapping a fault to its NTSTATUS or unavailability."""
    try:
        dce.request(request)
    except DCERPCException as exc:
        getter = getattr(exc, "get_error_code", None)
        if callable(getter):
            return int(getter()) & 0xFFFFFFFF
        raise MethodUnavailable(str(exc)) from exc
    return STATUS_SUCCESS


def set_secret_aes(dce: DCERPC_v5, secret_handle: object, session_key: bytes, value: bytes) -> int:
    """LsarSetSecret2 (opnum 138): set the secret's current value as an AES cipher value."""
    auth_data, salt, cipher = crypto.lsad_aead_encrypt(session_key, value)
    cipher_value = ndr.LSAPR_AES_CIPHER_VALUE()
    cipher_value["AuthData"] = auth_data
    cipher_value["Salt"] = salt
    cipher_value["cbCipher"] = len(cipher)
    cipher_value["Cipher"] = list(cipher)
    request = ndr.LsarSetSecret2()
    request["SecretHandle"] = secret_handle
    request["EncryptedCurrentValue"] = cipher_value
    request["EncryptedOldValue"] = NULL
    return _request_status(dce, request)


def set_secret_des(dce: DCERPC_v5, secret_handle: object, session_key: bytes, value: bytes) -> int:
    """LsarSetSecret (opnum 29): set the secret's current value with the DES 5.1.2 cipher."""
    ciphertext = crypto.des_secret_encrypt(session_key, value)
    cipher_value = lsad.LSAPR_CR_CIPHER_VALUE()
    cipher_value["Length"] = len(ciphertext)
    cipher_value["MaximumLength"] = len(ciphertext)
    cipher_value["Buffer"] = list(ciphertext)
    request = lsad.LsarSetSecret()
    request["SecretHandle"] = secret_handle
    request["EncryptedCurrentValue"] = cipher_value
    request["EncryptedOldValue"] = NULL
    return _request_status(dce, request)
