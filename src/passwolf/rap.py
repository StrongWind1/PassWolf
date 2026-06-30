r"""RAP NetUserPasswordSet2 change (opcode 115) over SMB1 \PIPE\LANMAN.

This is the legacy Remote Administration Protocol password change, a self-service change that proves the
old cleartext password. It predates DCE/RPC SAMR and rides only on SMB1, so it reaches only legacy SMB1
Windows (NT 4.0 through Server 2008); modern domain controllers remove SMB1 and the \\PIPE\\LANMAN gateway is
unreachable. impacket has no RAP password support (examples/changepasswd.py notes the XACT-SMB path is
unimplemented), so the request is built by hand on impacket's raw SMB1 SMB_COM_TRANSACTION primitive.

Spec mapping: [MS-RAP] 2.5.8.1 NetUserPasswordSet2 (opcode 115, ParamDesc "zb16b16WW"). The cleartext
passwords are uppercased before sending: the legacy gateway derives the LM OWF without OEM-uppercasing
the buffer itself, so an un-uppercased password fails old-password verification.

Opcode 115 is an obsolete LM-only path. Per [MS-RAP] 3.2.5.14 and the leaked Server 2003 xactsrv/changepw.c
(the cleartext branch), the gateway computes only the LM one-way functions of the old and new passwords and
calls SamrChangePasswordUser with LmPresent=TRUE, NtPresent=FALSE and no cross-encryption blobs, so it can
only store the new LM hash and never the NT hash (user.c:8848-8858). Issued directly over \\pipe\\samr that
LM-only change returns STATUS_SUCCESS yet leaves the NT hash unusable, so NTLM auth with the new password
fails; over the RAP gateway it instead returns Win32 0x3B (ERROR_UNEXP_NET_ERR, a session-class error from
the gateway's impersonated in-process SAM call). Either way it is not NTLM-usable. The working legacy RAP
change on SMB1 hosts is change_oem (opcode 214), which carries the RC4 OEM buffer keyed by the old LM
hash. Unlike the cleartext opcode 115, opcode 214 is NOT LM-only and does NOT blank the NT hash: the
server decrypts the OEM cleartext and recomputes and stores a real NT OWF (and LM OWF) from it
(SamOEMChangePasswordUser2 -> SampChangePasswordUser2 -> SampCalculateLmAndNtOwfPasswords ->
SampStoreUserPasswords with NtPresent=TRUE; [MS-SAMR] 3.1.5.10.2). Because the stored NT is computed over
the exact OEM bytes, the buffer carries the original-case password (build_oem_password_buffer), making the
new password NTLM-usable. Live-validated on Server 2003, Windows XP, and Server 2022: the post-change NT
equals nt_owf of the new password and the empty-password NT never appears.
"""

from __future__ import annotations

import contextlib
import os
from struct import pack
from typing import TYPE_CHECKING

from impacket.smb import (
    SMB,
    NewSMBPacket,
    SMBCommand,
    SMBTransaction_Data,
    SMBTransaction_Parameters,
    SMBTransactionResponse_Parameters,
)
from impacket.smbconnection import SMB_DIALECT, SMBConnection

from . import crypto
from .errors import MethodUnavailable, OperationFailed
from .nterror import STATUS_SUCCESS

if TYPE_CHECKING:
    from .model import Secret, Target

LANMAN = b"\\PIPE\\LANMAN\x00"
RAP_OPCODE_NETUSERPASSWORDSET2 = 0x0073  # [MS-RAP] 2.5.8.1, opcode 115 (cleartext change)
RAP_OPCODE_SAMOEMCHANGEPASSWORDUSER2 = 0x00D6  # opcode 214, undocumented RC4 OEM change (leaked changepw.c)
RAP_PASSWORD_FIELD_BYTES = 16  # b16: NUL-terminated OEM password, zero padded
RAP_PASSWORD_MAX_CHARS = 15  # keep room for the terminator inside the 16-byte field
_SMB1_TRANSACTION_DATA_BASE = 55  # SMB header + SMB_COM_TRANSACTION response word/byte counts
_SMB_DIRECT_PORT = 445  # direct-host SMB; legacy NetBIOS (139) needs the *SMBSERVER called name


def _connect(target: Target, bind_user: str, bind_password: str, bind_domain: str) -> tuple[SMBConnection, SMB, int]:
    """Force SMB1 (the only dialect that carries RAP), log in, and open an IPC$ tree.

    Returns the connection, the raw SMB1 server object (exposing sendSMB/recvSMB), and the IPC$ tree id.
    """
    port = int(os.environ.get("SMB_PORT", str(_SMB_DIRECT_PORT)))
    name = target.dc if port == _SMB_DIRECT_PORT else "*SMBSERVER"
    try:
        conn = SMBConnection(remoteName=name, remoteHost=target.dc, sess_port=port, preferredDialect=SMB_DIALECT)
        conn.login(bind_user, bind_password, bind_domain)
    except Exception as exc:
        msg = f"the RAP change needs an SMB1 \\PIPE\\LANMAN gateway, unavailable on this host: {exc}"
        raise MethodUnavailable(msg) from exc
    smb1 = conn.getSMBServer()
    tid = conn.connectTree("IPC$")
    return conn, smb1, tid


def _pad_password(password: str) -> bytes:
    """Build a 16-byte NUL-terminated OEM password field per [MS-RAP] 2.5.8.1.1."""
    raw = password.encode("ascii", "replace")[:RAP_PASSWORD_MAX_CHARS]
    return raw + b"\x00" * (RAP_PASSWORD_FIELD_BYTES - len(raw))


def _rap_transact(smb1: SMB, tid: int, param: bytes, data: bytes = b"") -> int:
    """Send a RAP request in an SMB_COM_TRANSACTION and return the RAP status WORD.

    The RAP result is the Status WORD at the front of the transaction parameter block; the SMB transaction
    layer itself returns STATUS_SUCCESS even when the RAP status is an error. MaxDataCount is capped at the
    negotiated buffer size because the legacy servers reject an over-large count before reading the opcode.
    ``data`` carries the optional Trans_Data send buffer (the opcode-214 password buffer rides here).
    """
    maxbuf = smb1._dialects_parameters["MaxBufferSize"]  # noqa: SLF001 - impacket exposes this only privately
    pkt = NewSMBPacket()
    pkt["Tid"] = tid
    command = SMBCommand(SMB.SMB_COM_TRANSACTION)
    command["Parameters"] = SMBTransaction_Parameters()
    command["Data"] = SMBTransaction_Data()
    command["Parameters"]["Setup"] = b""
    command["Parameters"]["TotalParameterCount"] = len(param)
    command["Parameters"]["TotalDataCount"] = len(data)
    command["Parameters"]["MaxParameterCount"] = min(1024, maxbuf)
    command["Parameters"]["MaxDataCount"] = maxbuf
    command["Parameters"]["ParameterCount"] = len(param)
    command["Parameters"]["ParameterOffset"] = 32 + 3 + 28 + len(LANMAN)
    command["Parameters"]["DataCount"] = len(data)
    command["Parameters"]["DataOffset"] = command["Parameters"]["ParameterOffset"] + len(param)
    command["Data"]["Name"] = LANMAN
    command["Data"]["Trans_Parameters"] = param
    command["Data"]["Trans_Data"] = data
    pkt.addCommand(command)
    smb1.sendSMB(pkt)
    resp = smb1.recvSMB()

    tparams = b""
    with contextlib.suppress(Exception):
        reply = SMBCommand(resp["Data"][0])
        prm = SMBTransactionResponse_Parameters(reply["Parameters"])
        block = reply["Data"]
        offset = prm["ParameterOffset"] - (_SMB1_TRANSACTION_DATA_BASE + prm["SetupCount"] * 2)
        tparams = block[offset : offset + prm["ParameterCount"]]
    if len(tparams) < 2:  # noqa: PLR2004 - a RAP reply always leads with a 2-byte status WORD
        msg = "the RAP gateway returned no status word; the \\PIPE\\LANMAN path is not answering"
        raise OperationFailed(msg)
    return int.from_bytes(tparams[0:2], "little")


def change(target: Target, user_name: str, old: Secret, new_password: str) -> int:
    """RAP NetUserPasswordSet2 (opcode 115): change a password by proving the old cleartext password.

    Returns STATUS_SUCCESS on a RAP status of 0; raises OperationFailed with the RAP Win32 code otherwise.
    Both passwords are uppercased to match the legacy gateway's LM-OWF derivation. This is the obsolete
    LM-only path (see the module docstring): the server updates only the LM hash, so accounts with a stored
    NT hash reject it (Win32 0x3B) and the result is not NTLM-usable. Prefer change_oem for legacy hosts.
    """
    if old.password is None:
        msg = "the RAP change requires the cleartext old password (it cannot use an NT hash)"
        raise MethodUnavailable(msg)
    old_upper = old.password.upper()
    new_upper = new_password.upper()
    conn, smb1, tid = _connect(target, user_name, old.password, target.domain)
    try:
        param = pack("<H", RAP_OPCODE_NETUSERPASSWORDSET2)
        param += b"zb16b16WW\x00"  # ParamDesc: UserName(z), OldPassword(b16), NewPassword(b16), Encrypted(W), RealLength(W)
        param += b"\x00"  # DataDesc: empty
        param += user_name.encode("ascii", "replace") + b"\x00"
        param += _pad_password(old_upper)
        param += _pad_password(new_upper)
        param += pack("<H", 0)  # EncryptedPassword = 0 (cleartext)
        param += pack("<H", len(new_upper))  # RealPasswordLength
        status = _rap_transact(smb1, tid, param)
    finally:
        with contextlib.suppress(Exception):
            conn.close()
    if status != 0:
        msg = f"RAP NetUserPasswordSet2 failed with Win32 status 0x{status:04X}"
        raise OperationFailed(msg)
    return STATUS_SUCCESS


def change_oem(target: Target, user_name: str, old: Secret, new_password: str) -> int:
    r"""RAP SamOEMChangePasswordUser2 (undocumented opcode 214 / 0xD6): the RC4 OEM change over SMB1.

    This is the SAMR opnum-54 OEM change (RC4 buffer keyed by the old LM OWF, plus an LM-OWF verifier)
    tunneled over \\PIPE\\LANMAN instead of \\pipe\\samr. The 532-byte send buffer (516-byte RC4 password
    buffer + 16-byte verifier) rides in the SMB transaction data field; the param block carries the
    ParamDesc "zsT" / DataDesc "B516B16" descriptors and the buffer length in 16-bit words. Like the OEM
    SAMR change it proves the old cleartext password and reaches only SMB1 hosts that still store LM hashes.
    """
    if old.password is None:
        msg = "the RAP OEM change requires the cleartext old password (it derives the LM OWF from it)"
        raise MethodUnavailable(msg)
    old_lm = crypto.lm_owf(old.password)
    new_lm = crypto.lm_owf(new_password)
    send_buffer = crypto.build_oem_password_buffer(new_password, old_lm) + crypto.des_owf_encrypt(old_lm, new_lm)
    conn, smb1, tid = _connect(target, user_name, old.password, target.domain)
    try:
        param = pack("<H", RAP_OPCODE_SAMOEMCHANGEPASSWORDUSER2)
        param += b"zsT\x00"  # ParamDesc: UserName(z), send-buffer pointer(s), send-buffer length in words(T)
        param += b"B516B16\x00"  # DataDesc: 516-byte encrypted password buffer + 16-byte verifier
        param += user_name.encode("ascii", "replace") + b"\x00"
        param += pack("<H", len(send_buffer) // 2)  # T: send buffer length in 16-bit words
        status = _rap_transact(smb1, tid, param, send_buffer)
    finally:
        with contextlib.suppress(Exception):
            conn.close()
    if status != 0:
        msg = f"RAP SamOEMChangePasswordUser2 failed with Win32 status 0x{status:04X}"
        raise OperationFailed(msg)
    return STATUS_SUCCESS
