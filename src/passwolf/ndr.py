"""NDR structures impacket does not model.

These are the wire types for the AES and undocumented paths: SAMR opnum 73 (AES change), the AES reset
info level UserInternal7, the undocumented SAMR opnum 63 diagnostic change, LSA opnum 138 (AES secret),
and Netlogon opnum 6 (DES OWF machine change). Importing this module also splices the UserInternal7 arm
into impacket's SAMPR_USER_INFO_BUFFER union so SamrSetInformationUser2 can carry it.

Spec mapping: [MS-SAMR] 2.2.6.32 (SAMPR_ENCRYPTED_PASSWORD_AES), 2.2.6.30 (UserInternal7),
3.1.5.10.4 (opnum 73); leaked samrpc.idl line 1550 (opnum 63); [MS-LSAD] 2.2.6.2 (AES cipher value),
3.1.4.6.9 (LsarSetSecret2); [MS-NRPC] 3.5.4.4.7 (NetrServerPasswordSet).
"""

from __future__ import annotations

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import ULONG, ULONGLONG
from impacket.dcerpc.v5.lsad import LSAPR_HANDLE
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUniConformantArray
from impacket.dcerpc.v5.nrpc import (
    ENCRYPTED_NT_OWF_PASSWORD,
    LPWSTR,
    NETLOGON_AUTHENTICATOR,
    NETLOGON_SECURE_CHANNEL_TYPE,
    WSTR,
)
from impacket.dcerpc.v5.samr import (
    DOMAIN_PASSWORD_INFORMATION,
    PENCRYPTED_LM_OWF_PASSWORD,
    PENCRYPTED_NT_OWF_PASSWORD,
    PRPC_UNICODE_STRING,
    PSAMPR_ENCRYPTED_USER_PASSWORD,
    RPC_UNICODE_STRING,
)

from .constants import (
    OPNUM_LSAD_SET_SECRET2,
    OPNUM_NRPC_SERVER_PASSWORD_SET,
    OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER3,
    OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER4,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)

_AES_STRUCT_ALIGNMENT = 8

# impacket's DCERPC_v5.request() resolves the session-error class for a non-zero NTSTATUS by name from the
# request class's own module (getattr(<module>, "DCERPCSessionError")). The NDR calls hosted here live in
# this module, so without this binding a real server rejection (a non-zero status that is not a DCE/RPC
# fault code) raises AttributeError instead of a typed error. The hosted calls return SAMR-style NTSTATUS
# codes, so we expose impacket's SAMR session error, which the SAMR method handlers already catch by type.
DCERPCSessionError = samr.DCERPCSessionError


# --- A conformant array of bytes behind a referent pointer (Cipher fields) ---
class _ByteConformantArray(NDRUniConformantArray):
    """[size_is(cb)] PUCHAR: a conformant UCHAR array."""

    item = "c"


class _PByteConformantArray(NDRPOINTER):
    """Referent pointer to a conformant byte array."""

    referent = (("Data", _ByteConformantArray),)


# --- [MS-SAMR] 2.2.6.32 SAMPR_ENCRYPTED_PASSWORD_AES ---
class SAMPR_ENCRYPTED_PASSWORD_AES(NDRSTRUCT):
    """The AES-encrypted SAM password buffer (AuthData, Salt, cbCipher, Cipher, PBKDF2Iterations)."""

    structure = (
        ("AuthData", "64s=b''"),
        ("Salt", "16s=b''"),
        ("cbCipher", ULONG),
        ("Cipher", _PByteConformantArray),
        ("PBKDF2Iterations", ULONGLONG),
    )

    def getAlignment(self) -> int:
        """Return the 8-byte alignment forced by the ULONGLONG member."""
        return _AES_STRUCT_ALIGNMENT


# --- [MS-SAMR] 3.1.5.10.4 SamrUnicodeChangePasswordUser4 (Opnum 73) ---
class SamrUnicodeChangePasswordUser4(NDRCALL):
    """Handle-less AES password change; EncryptedPassword is passed by value, not as a pointer."""

    opnum = OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER4
    structure = (
        ("ServerName", PRPC_UNICODE_STRING),
        ("UserName", RPC_UNICODE_STRING),
        ("EncryptedPassword", SAMPR_ENCRYPTED_PASSWORD_AES),
    )


class SamrUnicodeChangePasswordUser4Response(NDRCALL):
    """Response carrying the NTSTATUS in ErrorCode."""

    structure = (("ErrorCode", ULONG),)


# --- [MS-SAMR] 2.2.6.30 SAMPR_USER_INTERNAL7_INFORMATION (AES reset, info level 31) ---
class SAMPR_USER_INTERNAL7_INFORMATION(NDRSTRUCT):
    """The AES reset payload: an encrypted password buffer plus the password-expired flag."""

    structure = (
        ("Password", SAMPR_ENCRYPTED_PASSWORD_AES),
        ("PasswordExpired", "B=0"),
    )

    def getAlignment(self) -> int:
        """Return the 8-byte alignment of the embedded AES password structure."""
        return _AES_STRUCT_ALIGNMENT


# Splice the AES reset arm (level 31) into impacket's SAMPR_USER_INFO_BUFFER union.
samr.SAMPR_USER_INFO_BUFFER.union[USER_INTERNAL7_INFORMATION] = ("Internal7", SAMPR_USER_INTERNAL7_INFORMATION)


# --- [MS-SAMR] 2.2.6.31 SAMPR_USER_INTERNAL8_INFORMATION (AES reset, info level 32) ---
class SAMPR_USER_INTERNAL8_INFORMATION(NDRSTRUCT):
    """The AES reset payload that also carries the full user attribute block (SAMPR_USER_ALL_INFORMATION).

    Layout mirrors impacket's RC4 analogue SAMPR_USER_INTERNAL4_INFORMATION_NEW: the all-information
    block first, then the separate AES-encrypted password. WhichFields in I1 gates which attributes the
    server applies; the password is always taken from UserPassword.
    """

    structure = (
        ("I1", samr.SAMPR_USER_ALL_INFORMATION),
        ("UserPassword", SAMPR_ENCRYPTED_PASSWORD_AES),
    )


# Splice the AES all-information reset arm (level 32) into the same union.
samr.SAMPR_USER_INFO_BUFFER.union[USER_INTERNAL8_INFORMATION] = ("Internal8", SAMPR_USER_INTERNAL8_INFORMATION)


# --- Undocumented SamrUnicodeChangePasswordUser3 (Opnum 63), leaked samrpc.idl line 1550 ---
class USER_PWD_CHANGE_FAILURE_INFORMATION(NDRSTRUCT):
    """Structured rejection reason returned by opnum 63: an extended reason and a filter module name."""

    structure = (
        ("ExtendedFailureReason", ULONG),
        ("FilterModuleName", RPC_UNICODE_STRING),
    )


class PUSER_PWD_CHANGE_FAILURE_INFORMATION(NDRPOINTER):
    """Referent pointer to the failure information structure."""

    referent = (("Data", USER_PWD_CHANGE_FAILURE_INFORMATION),)


class PDOMAIN_PASSWORD_INFORMATION(NDRPOINTER):
    """Referent pointer to the effective password policy returned by opnum 63."""

    referent = (("Data", DOMAIN_PASSWORD_INFORMATION),)


class SamrUnicodeChangePasswordUser3(NDRCALL):
    """The opnum 55 argument list plus an extra AdditionalData pointer; same RC4 buffer and DES verifier."""

    opnum = OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER3
    structure = (
        ("ServerName", PRPC_UNICODE_STRING),
        ("UserName", RPC_UNICODE_STRING),
        ("NewPasswordEncryptedWithOldNt", PSAMPR_ENCRYPTED_USER_PASSWORD),
        ("OldNtOwfPasswordEncryptedWithNewNt", PENCRYPTED_NT_OWF_PASSWORD),
        ("LmPresent", "<B"),
        ("NewPasswordEncryptedWithOldLm", PSAMPR_ENCRYPTED_USER_PASSWORD),
        ("OldLmOwfPasswordEncryptedWithNewLmOrNt", PENCRYPTED_LM_OWF_PASSWORD),
        ("AdditionalData", PSAMPR_ENCRYPTED_USER_PASSWORD),
    )


class SamrUnicodeChangePasswordUser3Response(NDRCALL):
    """Response adding the effective policy and structured failure reason alongside the NTSTATUS."""

    structure = (
        ("EffectivePasswordPolicy", PDOMAIN_PASSWORD_INFORMATION),
        ("PasswordChangeInfo", PUSER_PWD_CHANGE_FAILURE_INFORMATION),
        ("ErrorCode", ULONG),
    )


# --- [MS-LSAD] 2.2.6.2 LSAPR_AES_CIPHER_VALUE and 3.1.4.6.9 LsarSetSecret2 (Opnum 138) ---
class LSAPR_AES_CIPHER_VALUE(NDRSTRUCT):
    """The AES-encrypted LSA secret value (AuthData, Salt, cbCipher, Cipher)."""

    structure = (
        ("AuthData", "64s=b''"),
        ("Salt", "16s=b''"),
        ("cbCipher", ULONG),
        ("Cipher", _PByteConformantArray),
    )

    def getAlignment(self) -> int:
        """Return the 8-byte alignment for the AES cipher value structure."""
        return _AES_STRUCT_ALIGNMENT


class PLSAPR_AES_CIPHER_VALUE(NDRPOINTER):
    """Referent pointer to the AES cipher value."""

    referent = (("Data", LSAPR_AES_CIPHER_VALUE),)


class LsarSetSecret2(NDRCALL):
    """Set an LSA secret using the AES (5.1.5) cipher value."""

    opnum = OPNUM_LSAD_SET_SECRET2
    structure = (
        ("SecretHandle", LSAPR_HANDLE),
        ("EncryptedCurrentValue", PLSAPR_AES_CIPHER_VALUE),
        ("EncryptedOldValue", PLSAPR_AES_CIPHER_VALUE),
    )


class LsarSetSecret2Response(NDRCALL):
    """Empty response (status carried by the RPC fault path)."""

    structure = ()


# --- [MS-NRPC] 3.5.4.4.7 NetrServerPasswordSet (Opnum 6) ---
class NetrServerPasswordSet(NDRCALL):
    """Legacy machine/trust change carrying a DES-encrypted NT OWF of the new password."""

    opnum = OPNUM_NRPC_SERVER_PASSWORD_SET
    structure = (
        ("PrimaryName", LPWSTR),
        ("AccountName", WSTR),
        ("SecureChannelType", NETLOGON_SECURE_CHANNEL_TYPE),
        ("ComputerName", WSTR),
        ("Authenticator", NETLOGON_AUTHENTICATOR),
        ("UasNewPassword", ENCRYPTED_NT_OWF_PASSWORD),
    )


class NetrServerPasswordSetResponse(NDRCALL):
    """Response with the return authenticator and the NTSTATUS error code."""

    structure = (
        ("ReturnAuthenticator", NETLOGON_AUTHENTICATOR),
        ("ErrorCode", ULONG),
    )
