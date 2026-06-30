"""SAMR change and reset methods.

This module wires the verified SAMR password operations: the AES change (opnum 73) and the legacy RC4,
OEM, and DES changes (55, 54, 38), the undocumented diagnostic change (63), the AES and RC4 cleartext
resets and the set-hash reset (SamrSetInformationUser2 info levels 31, 26-derived helper, and 18), and
the DSRM reset (opnum 66). impacket helpers are used where they are correct; the AES and opnum-63 paths
impacket lacks are built on the NDR types in :mod:`passwolf.ndr` and the crypto in :mod:`passwolf.crypto`.
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import MSRPC_UUID_SAMR, DCERPCSessionError

from . import crypto, ndr
from .constants import (
    DOMAIN_USER_RID_ADMIN,
    OPNUM_SAMR_SET_INFORMATION_USER,
    OPNUM_SAMR_SET_INFORMATION_USER2,
    PBKDF2_ITERATIONS_DEFAULT,
    SAMP_SUPPORTED_FEATURE_AES,
    USER_ALL_INFORMATION,
    USER_ALL_LMPASSWORDPRESENT,
    USER_ALL_NTPASSWORDPRESENT,
    USER_ALL_PASSWORDEXPIRED,
    USER_INTERNAL1_INFORMATION,
    USER_INTERNAL4_INFORMATION,
    USER_INTERNAL4_INFORMATION_NEW,
    USER_INTERNAL5_INFORMATION,
    USER_INTERNAL5_INFORMATION_NEW,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)
from .errors import MethodUnavailable
from .nterror import STATUS_LM_CROSS_ENCRYPTION_REQUIRED, STATUS_NT_CROSS_ENCRYPTION_REQUIRED

if TYPE_CHECKING:
    from collections.abc import Iterator

    from impacket.dcerpc.v5.ndr import NDR
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5

    from .model import Secret

LOG = logging.getLogger("passwolf.samr")

SAMR_PIPE = r"\samr"
SAMR_UUID = MSRPC_UUID_SAMR
_NONCE_BYTES = 16


def _ndr_field_strings(struct_obj: NDR, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Walk a parsed NDR structure and yield every leaf field as a (dotted-path, string) pair.

    Used to dump a whole response body under ``-v`` verbatim, so the operator sees every field that came
    off the wire — not just the handful the method curates into the result. Nested NDRSTRUCTs (large
    integers, RPC_UNICODE_STRINGs) recurse by their declared ``structure``; a null referent deserializes
    to empty bytes and is rendered as ``(empty)``; raw byte fields are shown as hex.
    """
    fields = getattr(type(struct_obj), "structure", None)
    if not fields:
        return
    for name, _ in fields:
        value = struct_obj[name]
        path = f"{prefix}{name}"
        if getattr(type(value), "structure", None):
            yield from _ndr_field_strings(value, f"{path}.")
        elif isinstance(value, (bytes, bytearray)):
            yield path, bytes(value).hex() or "(empty)"
        else:
            yield path, str(value)


# --- Handle resolution ---
def open_user_handle(dce: DCERPC_v5, username: str, access: int = MAXIMUM_ALLOWED) -> tuple[object, int]:
    """Resolve ``username`` to an open SAMR user handle and its RID via the standard connect chain."""
    server_handle = samr.hSamrConnect(dce)["ServerHandle"]
    domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"]
    domain_name = next(d["Name"] for d in domains if d["Name"].lower() != "builtin")
    domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)["DomainId"]
    domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)["DomainHandle"]
    rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [username])["RelativeIds"]["Element"][0]
    user_handle = samr.hSamrOpenUser(dce, domain_handle, access, rid)["UserHandle"]
    return user_handle, rid


# --- Capability preflight ---
def supports_aes(dce: DCERPC_v5) -> bool | None:
    """Report whether the DC wants the AES password buffer, via the SamrConnect5 SupportedFeatures preflight.

    Returns True when the server advertises the AES feature bit (0x10, [MS-SAMR] 2.2.7.15 / 3.2.2.4),
    False when it explicitly does not, and None when SamrConnect5 (opnum 64) is unavailable (pre-Vista) or
    the response cannot be read, so the caller keeps its fault-based fallback rather than guessing.
    """
    try:
        response = samr.hSamrConnect5(dce)
    except DCERPCException:
        return None
    try:
        features = int(response["OutRevisionInfo"]["V1"]["SupportedFeatures"])
    except (KeyError, TypeError):
        return None
    return bool(features & SAMP_SUPPORTED_FEATURE_AES)


# --- Status helpers ---
def _request_status(dce: DCERPC_v5, request: object) -> int:
    """Send a raw NDR request and return the NTSTATUS, mapping an RPC fault to MethodUnavailable."""
    try:
        response = dce.request(request)
    except DCERPCSessionError as exc:
        return int(exc.get_error_code()) & 0xFFFFFFFF
    except DCERPCException as exc:
        raise MethodUnavailable(str(exc)) from exc
    return int(response["ErrorCode"]) & 0xFFFFFFFF


def _old_nt_hash(old: Secret) -> bytes:
    """Resolve the account NT hash from a cleartext old password or a supplied NT hash."""
    if old.nt_hash is not None:
        return old.nt_hash
    if old.password is not None:
        return crypto.nt_owf(old.password)
    msg = "a change requires the current password or its NT hash"
    raise MethodUnavailable(msg)


# --- Change methods ---
def change_aes(dce: DCERPC_v5, server_name: str, user_name: str, new_password: str, old: Secret, iterations: int = PBKDF2_ITERATIONS_DEFAULT) -> int:
    """SamrUnicodeChangePasswordUser4 (opnum 73): the AES change, the only one Server 2025 accepts."""
    nt_hash = _old_nt_hash(old)
    nonce = os.urandom(_NONCE_BYTES)  # reused as PBKDF2 salt, AES IV, and the wire Salt
    cek = crypto.pbkdf2_sam_cek(nt_hash, nonce, iterations)
    plaintext = crypto.build_aes_password_buffer(new_password)
    auth_data, salt, cipher = crypto.sam_aead_encrypt(cek, plaintext, iv=nonce)

    request = ndr.SamrUnicodeChangePasswordUser4()
    request["ServerName"] = server_name
    request["UserName"] = user_name
    encrypted = request["EncryptedPassword"]
    encrypted["AuthData"] = auth_data
    encrypted["Salt"] = salt
    encrypted["cbCipher"] = len(cipher)
    encrypted["Cipher"] = list(cipher)
    encrypted["PBKDF2Iterations"] = iterations
    return _request_status(dce, request)


def change_rc4(dce: DCERPC_v5, user_name: str, new_password: str, old: Secret) -> int:
    """SamrUnicodeChangePasswordUser2 (opnum 55): the legacy RC4 change, via impacket."""
    nt_hex = old.nt_hash.hex() if old.nt_hash is not None else ""
    try:
        response = samr.hSamrUnicodeChangePasswordUser2(dce, serverName="\x00", userName=user_name, oldPassword=old.password or "", newPassword=new_password, oldPwdHashLM="", oldPwdHashNT=nt_hex)
    except DCERPCSessionError as exc:
        return int(exc.get_error_code()) & 0xFFFFFFFF
    except DCERPCException as exc:
        raise MethodUnavailable(str(exc)) from exc
    return int(response["ErrorCode"]) & 0xFFFFFFFF


def change_oem(dce: DCERPC_v5, user_name: str, new_password: str, old: Secret) -> int:
    """SamrOemChangePasswordUser2 (opnum 54): the OEM RC4 change, hand-built (impacket has no helper).

    Not LM-only and does not blank the NT hash: the server decrypts the OEM cleartext buffer and
    recomputes and stores a real NT OWF and LM OWF from it ([MS-SAMR] 3.1.5.10.2 step 9; Server 2003
    SampChangePasswordUser2 -> SampCalculateLmAndNtOwfPasswords -> SampStoreUserPasswords with
    NtPresent=TRUE). The buffer carries the original-case password (build_oem_password_buffer), so the
    stored NT is NTLM-usable with the exact new password. The old LM hash both keys the RC4 buffer and,
    cross-encrypted with the new LM, forms the verifier.
    """
    if old.password is None:
        msg = "the OEM change requires the cleartext old password (the LM hash cannot come from an NT hash)"
        raise MethodUnavailable(msg)
    old_lm = crypto.lm_owf(old.password)
    new_lm = crypto.lm_owf(new_password)
    request = samr.SamrOemChangePasswordUser2()
    request["ServerName"] = NULL
    request["UserName"] = user_name
    request["NewPasswordEncryptedWithOldLm"]["Buffer"] = crypto.build_oem_password_buffer(new_password, old_lm)
    # The OWF verifier field is a referent pointer (PENCRYPTED_LM_OWF_PASSWORD); impacket's own helpers
    # assign the raw 16-byte value to it, not a wrapped struct.
    request["OldLmOwfPasswordEncryptedWithNewLm"] = crypto.des_owf_encrypt(old_lm, new_lm)
    return _request_status(dce, request)


def _change_password_user_request(user_handle: object, old_nt: bytes, old_lm: bytes | None, new_nt: bytes, new_lm: bytes, *, nt_cross: bool, lm_cross: bool) -> object:
    """Build one SamrChangePasswordUser (opnum 38) request from the chosen presence flags.

    A fresh request is built per attempt on purpose: impacket NDRCALL structs do not re-serialize cleanly
    after a referent (NULL to pointer) field is flipped, so the cross-encryption retry must not mutate and
    resend a prior request. Each blob is one OWF DES-encrypted under another per [MS-SAMR] 2.2.11.1, so a
    field named "X encrypted with Y" is ``crypto.des_owf_encrypt(X, Y)``.
    """
    request = samr.SamrChangePasswordUser()
    request["UserHandle"] = user_handle
    # NT authentication: prove the old password (or its supplied NT hash) by the doubly-encrypted NT OWFs.
    request["NtPresent"] = 1
    request["OldNtEncryptedWithNewNt"] = crypto.des_owf_encrypt(old_nt, new_nt)
    request["NewNtEncryptedWithOldNt"] = crypto.des_owf_encrypt(new_nt, old_nt)
    # LM authentication is only possible from the cleartext old password (no LM OWF inside an NT hash).
    if old_lm is not None:
        request["LmPresent"] = 1
        request["OldLmEncryptedWithNewLm"] = crypto.des_owf_encrypt(old_lm, new_lm)
        request["NewLmEncryptedWithOldLm"] = crypto.des_owf_encrypt(new_lm, old_lm)
    else:
        request["LmPresent"] = 0
        request["OldLmEncryptedWithNewLm"] = NULL
        request["NewLmEncryptedWithOldLm"] = NULL
    if nt_cross:  # supply the new NT OWF cross-encrypted under the new LM OWF (account stored no NT hash)
        request["NtCrossEncryptionPresent"] = 1
        request["NewNtEncryptedWithNewLm"] = crypto.des_owf_encrypt(new_nt, new_lm)
    else:
        request["NtCrossEncryptionPresent"] = 0
        request["NewNtEncryptedWithNewLm"] = NULL
    if lm_cross:  # supply the new LM OWF cross-encrypted under the new NT OWF (account stored no LM hash)
        request["LmCrossEncryptionPresent"] = 1
        request["NewLmEncryptedWithNewNt"] = crypto.des_owf_encrypt(new_lm, new_nt)
    else:
        request["LmCrossEncryptionPresent"] = 0
        request["NewLmEncryptedWithNewNt"] = NULL
    return request


def change_des(dce: DCERPC_v5, user_handle: object, old: Secret, *, new_password: str | None = None, new_nt_hash: bytes | None = None, new_lm_hash: bytes | None = None) -> int:
    """SamrChangePasswordUser (opnum 38): the DES OWF cross-encryption change, hand-built with retry.

    Built by hand rather than via impacket's helper (which hardcodes ``LmPresent=0`` and never sends the
    NT cross-encryption) so it is correct for every stored-hash state. NT authentication is always sent; LM
    authentication is added when the cleartext old password is known (the LM OWF cannot be recovered from an
    NT hash, so a pass-the-hash change is NT-only). When the account stores only one of the two hashes the
    server authenticates on what it has and asks for the missing new hash cross-encrypted
    (STATUS_LM/NT_CROSS_ENCRYPTION_REQUIRED, [MS-SAMR] 3.1.5.10.1; leaked Server 2003 user.c:8892 / :9003).
    This mirrors SamiChangePasswordUser's retry loop (wrappers.c:7907-8103): on that signal, rebuild the
    request with the cross-encrypted new hash and resend.

    Pass ``new_nt_hash`` instead of ``new_password`` to set the new NT OWF directly with no cleartext (the
    only change method that can): NT-only, the new LM cross uses ``new_lm_hash`` or the empty-LM placeholder,
    matching impacket's hSamrChangePasswordUser. The old secret is still proved by the NT cross-encryption,
    so this needs no privilege, but it bypasses complexity/history, drops the Kerberos keys, and flags the
    password expired.
    """
    old_nt = _old_nt_hash(old)
    if new_nt_hash is not None:
        # Setting a raw NT OWF: the server stores whatever it is handed, so the new-LM cross rides along with
        # the supplied new LM or the empty-LM placeholder; the old secret is proved by the NT OWFs alone.
        new_lm = new_lm_hash if new_lm_hash is not None else crypto.lm_owf("")
        request = _change_password_user_request(user_handle, old_nt, None, new_nt_hash, new_lm, nt_cross=False, lm_cross=True)
        return _request_status(dce, request)

    if new_password is None:
        msg = "the DES change needs a new password (--target-new-password) or a new NT hash (--target-new-hash)"
        raise MethodUnavailable(msg)
    new_nt = crypto.nt_owf(new_password)
    new_lm = crypto.lm_owf(new_password)
    old_lm = crypto.lm_owf(old.password) if old.password is not None else None

    nt_cross = lm_cross = False
    status = _request_status(dce, _change_password_user_request(user_handle, old_nt, old_lm, new_nt, new_lm, nt_cross=nt_cross, lm_cross=lm_cross))
    for _ in range(2):  # an account is missing at most one stored hash, so at most one cross round is needed
        if status == STATUS_NT_CROSS_ENCRYPTION_REQUIRED and not nt_cross:
            nt_cross = True
        elif status == STATUS_LM_CROSS_ENCRYPTION_REQUIRED and not lm_cross:
            lm_cross = True
        else:
            break
        status = _request_status(dce, _change_password_user_request(user_handle, old_nt, old_lm, new_nt, new_lm, nt_cross=nt_cross, lm_cross=lm_cross))
    return status


def change_diag(dce: DCERPC_v5, server_name: str, user_name: str, new_password: str, old: Secret) -> tuple[int, dict[str, str]]:
    """SamrUnicodeChangePasswordUser3 (opnum 63): RC4 change with structured policy diagnostics.

    Returns the NTSTATUS and an extra map describing why the new password was refused: the effective
    DOMAIN_PASSWORD_INFORMATION (minimum length, history depth, minimum age) and the
    USER_PWD_CHANGE_FAILURE_INFORMATION extended reason. The whole point of this method is to surface
    those diagnostics, and the server returns them in the RESPONSE BODY alongside a non-zero ErrorCode
    (for example STATUS_PASSWORD_RESTRICTION) rather than as an RPC fault. impacket's DCERPC_v5.request()
    raises on that non-zero trailing status before the body can be read, which would throw the diagnostics
    away, so the call is issued with call()/recv() and the stub is parsed by hand. A genuine RPC fault
    (the opnum being unsupported, say) still raises and is reported as the method being unavailable. Both
    Server 2022 and the leaked Windows 2003 SAM populate the policy block on a restriction, so this is not
    server-version conditional (leaked samrpc.idl line 1550; confirmed live on Server 2022; Server 2003 behavior grounded in the leaked user.c handler).
    """
    old_nt = _old_nt_hash(old)
    new_nt = crypto.nt_owf(new_password)
    request = ndr.SamrUnicodeChangePasswordUser3()
    request["ServerName"] = server_name
    request["UserName"] = user_name
    request["NewPasswordEncryptedWithOldNt"]["Buffer"] = crypto.build_rc4_password_buffer(new_password, old_nt)
    # The OWF verifier field is a referent pointer (PENCRYPTED_NT_OWF_PASSWORD); assign the raw 16 bytes.
    request["OldNtOwfPasswordEncryptedWithNewNt"] = crypto.des_owf_encrypt(old_nt, new_nt)
    request["LmPresent"] = 0
    request["NewPasswordEncryptedWithOldLm"] = NULL
    request["OldLmOwfPasswordEncryptedWithNewLmOrNt"] = NULL
    request["AdditionalData"] = NULL

    # Send the request and take the raw stub back without impacket's status auto-raise, so the policy and
    # failure diagnostics in the body survive a rejected change.
    try:
        dce.call(request.opnum, request)
        stub = dce.recv()
    except DCERPCException as exc:
        raise MethodUnavailable(str(exc)) from exc
    response = ndr.SamrUnicodeChangePasswordUser3Response(stub)

    # Under -v, dump the entire parsed response body field-by-field, so every value off the wire is visible
    # even when it is not one of the curated diagnostics below. Guarded by isEnabledFor so the walk is skipped
    # at the default level.
    if LOG.isEnabledFor(logging.DEBUG):
        for path, value in _ndr_field_strings(response):
            LOG.debug("samr-diag wire %s = %s", path, value)

    # The server fills both out-structs only when the change fails with STATUS_PASSWORD_RESTRICTION and
    # NULLs them on every other status (leaked user.c:11565-11589). impacket deserializes a populated
    # referent into the struct directly (it auto-dereferences the [unique] pointer) and a null referent
    # into empty bytes, so a non-bytes value is the signal that the diagnostics are present.
    extra: dict[str, str] = {}
    policy = response["EffectivePasswordPolicy"]
    if not isinstance(policy, bytes):
        extra["min_password_length"] = str(policy["MinPasswordLength"])
        extra["password_history_length"] = str(policy["PasswordHistoryLength"])
        # MinPasswordAge is an OLD_LARGE_INTEGER holding a negative 100-nanosecond interval; report its
        # magnitude in days so the operator sees the whole policy reason, not just the length.
        ticks = (int(policy["MinPasswordAge"]["HighPart"]) << 32) | (int(policy["MinPasswordAge"]["LowPart"]) & 0xFFFFFFFF)
        extra["min_password_age_days"] = f"{abs(ticks) / (1e7 * 86400):.2f}"
    # USER_PWD_CHANGE_FAILURE_INFORMATION carries the extended reason (1 too-short, 2 in-history, 5
    # not-complex, 0 min-age); its FilterModuleName RPC_UNICODE_STRING names the password-filter DLL that
    # rejected the change. A null Buffer referent deserializes the whole field to empty bytes (same signal
    # the parent struct uses), so a non-bytes value means a filter DLL actually reported a name.
    change_info = response["PasswordChangeInfo"]
    if not isinstance(change_info, bytes):
        extra["change_failure_reason"] = str(int(change_info["ExtendedFailureReason"]))
        filter_field = change_info["FilterModuleName"]
        if not isinstance(filter_field, bytes):
            filter_name = str(filter_field["Buffer"] or "").strip("\x00")
            if filter_name:
                extra["filter_module_name"] = filter_name
    return int(response["ErrorCode"]) & 0xFFFFFFFF, extra


# --- Reset methods ---
def _aes_reset_blob(session_key: bytes, new_password: str) -> object:
    """Build the SAMPR_ENCRYPTED_PASSWORD_AES blob shared by the UserInternal7 and UserInternal8 resets.

    The content-encryption key is the 16-byte SMB session key directly (not PBKDF2); PBKDF2Iterations is
    sent as 0 and ignored by the server per [MS-SAMR] 3.1.5.6.4.
    """
    plaintext = crypto.build_aes_password_buffer(new_password)
    auth_data, salt, cipher = crypto.sam_aead_encrypt(session_key, plaintext)
    blob = ndr.SAMPR_ENCRYPTED_PASSWORD_AES()
    blob["AuthData"] = auth_data
    blob["Salt"] = salt
    blob["cbCipher"] = len(cipher)
    blob["Cipher"] = list(cipher)
    blob["PBKDF2Iterations"] = 0
    return blob


def reset_aes(dce: DCERPC_v5, user_handle: object, session_key: bytes | None, new_password: str, *, expire: bool) -> int:
    """SamrSetInformationUser2 + UserInternal7 (info level 31): the compact AES cleartext reset.

    The content-encryption key is the 16-byte SMB session key directly, so this path needs the named-pipe
    transport. This is the password-only AES reset (UserInternal7); the all-information AES form
    (UserInternal8) is reached through reset_set_information with --reset-info-class internal8.
    """
    if session_key is None:
        msg = "the AES reset needs the SMB session key; use the SMB transport, not TCP"
        raise MethodUnavailable(msg)
    request = samr.SamrSetInformationUser2()
    request["UserHandle"] = user_handle
    request["UserInformationClass"] = USER_INTERNAL7_INFORMATION
    request["Buffer"]["tag"] = USER_INTERNAL7_INFORMATION
    request["Buffer"]["Internal7"]["Password"] = _aes_reset_blob(session_key, new_password)
    request["Buffer"]["Internal7"]["PasswordExpired"] = 1 if expire else 0
    return _request_status(dce, request)


def _clear_all_information(all_info: samr.SAMPR_USER_ALL_INFORMATION, *, clear_owf: bool = True) -> None:
    """Zero every pointer field of a SAMPR_USER_ALL_INFORMATION so only WhichFields-flagged data is sent.

    Mirrors impacket's hSamrSetPasswordInternal4New: the all-information block carries no attribute changes
    for a password-only reset, so every variable-length member is set to NULL. ``clear_owf`` controls the
    NtOwfPassword/LmOwfPassword blobs: the cleartext and AES resets leave them NULL (the password rides a
    separate field), but the UserAllInformation hash set populates them and must NOT pre-NULL them first,
    because impacket does not re-establish a referent pointer once it has been set to NULL.
    """
    for field in ("UserName", "FullName", "HomeDirectory", "HomeDirectoryDrive", "ScriptPath", "ProfilePath", "AdminComment", "WorkStations", "UserComment", "Parameters"):
        all_info[field] = NULL
    if clear_owf:
        all_info["LmOwfPassword"]["Buffer"] = NULL
        all_info["NtOwfPassword"]["Buffer"] = NULL
    all_info["PrivateData"] = NULL
    all_info["SecurityDescriptor"]["SecurityDescriptor"] = NULL
    all_info["LogonHours"]["LogonHours"] = NULL


def reset_rc4(dce: DCERPC_v5, user_handle: object, session_key: bytes | None, new_password: str, *, expire: bool = True) -> int:
    """SamrSetInformationUser2 + UserInternal4InformationNew (level 25): the RC4 + MD5-salt cleartext reset.

    Built directly rather than via impacket's helper so the password-expiry flag is honored (the helper
    hardcodes it). The RC4 key is MD5(salt + SMB session key), so this path needs the named-pipe transport.
    """
    if session_key is None:
        msg = "the RC4 reset needs the SMB session key; use the SMB transport, not TCP"
        raise MethodUnavailable(msg)
    request = samr.SamrSetInformationUser2()
    request["UserHandle"] = user_handle
    request["UserInformationClass"] = USER_INTERNAL4_INFORMATION_NEW
    request["Buffer"]["tag"] = USER_INTERNAL4_INFORMATION_NEW
    internal4 = request["Buffer"]["Internal4New"]
    _clear_all_information(internal4["I1"])
    internal4["I1"]["WhichFields"] = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED
    internal4["I1"]["PasswordExpired"] = 1 if expire else 0
    internal4["UserPassword"]["Buffer"] = crypto.build_rc4_md5_password_buffer(new_password, session_key)
    return _request_status(dce, request)


def reset_hash(dce: DCERPC_v5, user_handle: object, session_key: bytes | None, nt_hash: bytes, lm_hash: bytes | None = None, *, expire: bool = True) -> int:
    """SamrSetInformationUser + UserInternal1Information: set the NT (and optionally LM) OWF directly.

    Each OWF half is DES-encrypted with the SMB session key per [MS-SAMR] 2.2.11.1.1, so this path needs
    the named-pipe transport. Supplying an LM hash sets it alongside the NT hash (the spec models both
    halves with independent presence flags); ``expire`` flags the account must-change-at-next-logon. This
    is the full policy bypass, including complexity and length.
    """
    if session_key is None:
        msg = "the set-hash reset needs the SMB session key; use the SMB transport, not TCP"
        raise MethodUnavailable(msg)
    request = samr.SamrSetInformationUser()
    request["UserHandle"] = user_handle
    request["UserInformationClass"] = USER_INTERNAL1_INFORMATION
    request["Buffer"]["tag"] = USER_INTERNAL1_INFORMATION
    internal1 = request["Buffer"]["Internal1"]
    internal1["EncryptedNtOwfPassword"] = crypto.des_owf_encrypt(nt_hash, session_key)
    internal1["NtPasswordPresent"] = 1
    if lm_hash is not None:
        internal1["EncryptedLmOwfPassword"] = crypto.des_owf_encrypt(lm_hash, session_key)
        internal1["LmPasswordPresent"] = 1
    else:
        internal1["EncryptedLmOwfPassword"] = b"\x00" * 16
        internal1["LmPasswordPresent"] = 0
    internal1["PasswordExpired"] = 1 if expire else 0
    return _request_status(dce, request)


def reset_rc4_unsalted(dce: DCERPC_v5, user_handle: object, session_key: bytes | None, new_password: str, *, expire: bool = True) -> int:
    """SamrSetInformationUser2 + UserInternal4Information (level 23): the unsalted RC4 cleartext reset.

    The legacy form of the RC4 reset: the password buffer is RC4-encrypted with the SMB session key
    directly, with no MD5 salt ([MS-SAMR] 3.2.2.1), so it needs the named-pipe transport. The salted
    UserInternal4InformationNew form (:func:`reset_rc4`) is preferred; this exists for completeness and
    for servers that only accept the unsalted level.
    """
    return reset_set_information(dce, user_handle, session_key, opnum=OPNUM_SAMR_SET_INFORMATION_USER2, info_class=USER_INTERNAL4_INFORMATION, new_password=new_password, expire=expire)


# --- Generic SamrSetInformationUser/User2 reset (advanced opnum + info-class control) ---
@dataclass(frozen=True)
class NewSecret:
    """The new secret for a reset: a cleartext password, or an NT (and optional LM) hash."""

    password: str | None = None
    nt_hash: bytes | None = None
    lm_hash: bytes | None = None

    def require_password(self) -> str:
        """Return the cleartext password or raise when a cleartext info class was given only a hash."""
        if self.password is None:
            msg = "this USER_INFORMATION_CLASS needs a cleartext password (--target-new-password)"
            raise MethodUnavailable(msg)
        return self.password

    def require_nt_hash(self) -> bytes:
        """Return the NT hash to set, deriving it from the cleartext password when no hash was supplied.

        A hash-carrying info class (UserInternal1, UserAllInformation) can take an explicit NT hash for a
        policy-bypass set, or a cleartext password that is hashed locally into its NT OWF. Only when
        neither is present is it an error.
        """
        if self.nt_hash is not None:
            return self.nt_hash
        if self.password is not None:
            return crypto.nt_owf(self.password)
        msg = "a hash-setting reset needs a new NT hash (--target-new-hash) or a cleartext password"
        raise MethodUnavailable(msg)


def _set_owf_short_blob(blob: samr.RPC_SHORT_BLOB, owf16: bytes) -> None:
    """Place a 16-byte encrypted OWF into a RPC_SHORT_BLOB whose Buffer is a USHORT array.

    The SAMPR_USER_ALL_INFORMATION OWF fields are length-counted blobs of 16-bit units; the 16-byte OWF
    is carried as eight little-endian USHORTs, with Length/MaximumLength in bytes ([MS-SAMR] 3.1.5.6.4.1
    maps Internal1.NtOwfPassword to All.NtOwfPassword with Length 0x10).
    """
    blob["Length"] = len(owf16)
    blob["MaximumLength"] = len(owf16)
    blob["Buffer"] = list(struct.unpack(f"<{len(owf16) // 2}H", owf16))


def _build_internal1(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal1Information (18): the dedicated NT/LM OWF set-hash structure."""
    arm = buf["Internal1"]
    arm["EncryptedNtOwfPassword"] = crypto.des_owf_encrypt(secret.require_nt_hash(), session_key)
    arm["NtPasswordPresent"] = 1
    if secret.lm_hash is not None:
        arm["EncryptedLmOwfPassword"] = crypto.des_owf_encrypt(secret.lm_hash, session_key)
        arm["LmPasswordPresent"] = 1
    else:
        arm["EncryptedLmOwfPassword"] = b"\x00" * 16
        arm["LmPasswordPresent"] = 0
    arm["PasswordExpired"] = 1 if expire else 0


def _build_userall(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserAllInformation (21): the same NT/LM OWF set-hash carried in the all-information block."""
    arm = buf["All"]
    _clear_all_information(arm, clear_owf=False)
    fields = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED
    _set_owf_short_blob(arm["NtOwfPassword"], crypto.des_owf_encrypt(secret.require_nt_hash(), session_key))
    arm["NtPasswordPresent"] = 1
    if secret.lm_hash is not None:
        fields |= USER_ALL_LMPASSWORDPRESENT
        _set_owf_short_blob(arm["LmOwfPassword"], crypto.des_owf_encrypt(secret.lm_hash, session_key))
        arm["LmPasswordPresent"] = 1
    arm["WhichFields"] = fields
    arm["PasswordExpired"] = 1 if expire else 0


def _build_internal4(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal4Information (23): cleartext RC4 (unsalted) in the all-information wrapper."""
    arm = buf["Internal4"]
    _clear_all_information(arm["I1"])
    arm["I1"]["WhichFields"] = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED
    arm["I1"]["PasswordExpired"] = 1 if expire else 0
    arm["UserPassword"]["Buffer"] = crypto.build_rc4_password_buffer(secret.require_password(), session_key)


def _build_internal5(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal5Information (24): cleartext RC4 (unsalted), password-only structure."""
    arm = buf["Internal5"]
    arm["UserPassword"]["Buffer"] = crypto.build_rc4_password_buffer(secret.require_password(), session_key)
    arm["PasswordExpired"] = 1 if expire else 0


def _build_internal4new(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal4InformationNew (25): cleartext RC4 + MD5 salt in the all-information wrapper."""
    arm = buf["Internal4New"]
    _clear_all_information(arm["I1"])
    arm["I1"]["WhichFields"] = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED
    arm["I1"]["PasswordExpired"] = 1 if expire else 0
    arm["UserPassword"]["Buffer"] = crypto.build_rc4_md5_password_buffer(secret.require_password(), session_key)


def _build_internal5new(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal5InformationNew (26): cleartext RC4 + MD5 salt, password-only structure."""
    arm = buf["Internal5New"]
    arm["UserPassword"]["Buffer"] = crypto.build_rc4_md5_password_buffer(secret.require_password(), session_key)
    arm["PasswordExpired"] = 1 if expire else 0


def _build_internal7(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal7Information (31): cleartext AES, password-only structure."""
    arm = buf["Internal7"]
    arm["Password"] = _aes_reset_blob(session_key, secret.require_password())
    arm["PasswordExpired"] = 1 if expire else 0


def _build_internal8(buf: samr.SAMPR_USER_INFO_BUFFER, session_key: bytes, secret: NewSecret, *, expire: bool) -> None:
    """UserInternal8Information (32): cleartext AES in the all-information wrapper."""
    arm = buf["Internal8"]
    _clear_all_information(arm["I1"])
    arm["I1"]["WhichFields"] = USER_ALL_NTPASSWORDPRESENT | USER_ALL_PASSWORDEXPIRED
    arm["I1"]["PasswordExpired"] = 1 if expire else 0
    arm["UserPassword"] = _aes_reset_blob(session_key, secret.require_password())


# Every settable password-bearing USER_INFORMATION_CLASS and the builder that fills its union arm. The
# server re-maps several of these (5->4, 5New->4New, 7->8, and 1 into the All block), but each is a
# distinct wire shape, so all eight are offered for the advanced --reset-info-class control.
_RESET_BUILDERS = {
    USER_INTERNAL1_INFORMATION: _build_internal1,
    USER_ALL_INFORMATION: _build_userall,
    USER_INTERNAL4_INFORMATION: _build_internal4,
    USER_INTERNAL5_INFORMATION: _build_internal5,
    USER_INTERNAL4_INFORMATION_NEW: _build_internal4new,
    USER_INTERNAL5_INFORMATION_NEW: _build_internal5new,
    USER_INTERNAL7_INFORMATION: _build_internal7,
    USER_INTERNAL8_INFORMATION: _build_internal8,
}


def reset_set_information(
    dce: DCERPC_v5,
    user_handle: object,
    session_key: bytes | None,
    *,
    opnum: int,
    info_class: int,
    new_password: str | None = None,
    nt_hash: bytes | None = None,
    lm_hash: bytes | None = None,
    expire: bool,
) -> int:
    """Reset over an explicit opnum and USER_INFORMATION_CLASS (the advanced control path).

    ``opnum`` is 37 (SamrSetInformationUser) or 58 (SamrSetInformationUser2); the spec makes 37 behave
    identically ([MS-SAMR] 3.1.5.6.5), so any of the eight settable password classes works on either,
    though older servers reject the newer (_NEW/AES) levels on opnum 37. The info class selects the
    cipher and structure; the matching builder enforces password-vs-hash. All SAMR resets borrow the
    SMB session key to protect the buffer, so the named-pipe transport is required.
    """
    if session_key is None:
        msg = "SAMR resets need the SMB session key; use the SMB transport, not TCP"
        raise MethodUnavailable(msg)
    builder = _RESET_BUILDERS.get(info_class)
    if builder is None:
        msg = f"USER_INFORMATION_CLASS {info_class} is not a settable password class"
        raise MethodUnavailable(msg)
    request = samr.SamrSetInformationUser() if opnum == OPNUM_SAMR_SET_INFORMATION_USER else samr.SamrSetInformationUser2()
    request["UserHandle"] = user_handle
    request["UserInformationClass"] = info_class
    request["Buffer"]["tag"] = info_class
    builder(request["Buffer"], session_key, NewSecret(password=new_password, nt_hash=nt_hash, lm_hash=lm_hash), expire=expire)
    return _request_status(dce, request)


def reset_dsrm(dce: DCERPC_v5, new_password: str) -> int:
    """SamrSetDSRMPassword (opnum 66): set the DC-local recovery (RID 500) password.

    The wire value is the new NT OWF DES-encrypted under a key derived from the RID. The server forces
    UserId to 500 and serves this only over the named pipe.
    """
    nt_owf = crypto.nt_owf(new_password)
    encrypted = crypto.des_owf_encrypt(nt_owf, crypto.rid_to_des_key(DOMAIN_USER_RID_ADMIN))
    request = samr.SamrSetDSRMPassword()
    request["Unused"] = NULL
    request["UserId"] = DOMAIN_USER_RID_ADMIN
    # EncryptedNtOwfPassword is a referent pointer (impacket types it PENCRYPTED_LM_OWF_PASSWORD); assign
    # the raw 16 bytes directly, not a wrapped ENCRYPTED_*_OWF_PASSWORD struct (matches change_oem/des).
    request["EncryptedNtOwfPassword"] = encrypted
    return _request_status(dce, request)
