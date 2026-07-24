# SPDX-License-Identifier: Apache-2.0
"""Netlogon machine and trust password change.

A machine or trust account changes its own password by proving the current secret through a secure
channel (NetrServerReqChallenge + NetrServerAuthenticate3), then writing the new secret. Modern DCs
enforce a sealed channel (the post-CVE-2020-1472 hardening), so the bound channel is upgraded to
RPC_C_AUTHN_NETLOGON sign+seal before the write. Two writes are supported: the AES NL_TRUST_PASSWORD
buffer (opnum 30) and the legacy DES OWF (opnum 6), which Server 2025 still accepts over a sealed channel.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import epm, nrpc, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.nrpc import ENCRYPTED_NT_OWF_PASSWORD, MSRPC_UUID_NRPC, NETLOGON_SECURE_CHANNEL_TYPE
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_NETLOGON, DCERPCException

from . import crypto, ndr
from .constants import NETLOGON_FLAGS_AES
from .errors import MethodUnavailable
from .model import AccountKind
from .nterror import STATUS_SUCCESS

if TYPE_CHECKING:
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5

    from .model import Secret, Target

CLIENT_CHALLENGE = b"passwolf"  # 8 bytes, fixed client challenge for the channel bootstrap


def channel_type_for(kind: AccountKind) -> int:
    """Map an account kind to its Netlogon secure-channel type.

    A trust is addressed by its flat NetBIOS name plus the trailing '$' (the form _sam_account
    produces), which is the TrustedDomainSecureChannel. The server keys the trust-account lookup off the
    (name form, channel type) pair: the DNS-name form ("contoso.com") authenticates only over
    TrustedDnsDomainSecureChannel, while the flat-name form ("CONTOSO$") authenticates only over
    TrustedDomainSecureChannel ([MS-NRPC] 3.5.4.4.2, NetrServerAuthenticate3 returns
    STATUS_NO_TRUST_SAM_ACCOUNT on a mismatch; confirmed live against a forged interdomain trust).
    """
    if kind is AccountKind.TRUST:
        return NETLOGON_SECURE_CHANNEL_TYPE.TrustedDomainSecureChannel
    return NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel


def _nt_hash_of(secret: Secret) -> bytes:
    """Resolve the account's current NT hash from its cleartext machine password or a supplied hash."""
    if secret.nt_hash is not None:
        return secret.nt_hash
    if secret.password is not None:
        return crypto.nt_owf(secret.password)
    msg = "a machine or trust change requires the current password or its NT hash"
    raise MethodUnavailable(msg)


def _sam_account(account: str) -> str:
    """Return the SAM account name with the trailing '$' (computer accounts are stored that way)."""
    return account if account.endswith("$") else account + "$"


def open_secure_channel(target: Target, netbios_domain: str, account: str, channel_type: int, secret: Secret) -> tuple[DCERPC_v5, bytes, bytes]:
    """Build and seal a Netlogon secure channel, returning (dce, session_key, client_credential)."""
    sam = _sam_account(account)
    computer = sam[:-1]
    nt_hash = _nt_hash_of(secret)

    binding = epm.hept_map(target.dc, MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
    rpc = transport.DCERPCTransportFactory(binding)
    rpc.set_credentials(sam, secret.password or "", netbios_domain, "", nt_hash.hex())
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_NRPC)

    try:
        server_challenge = nrpc.hNetrServerReqChallenge(dce, NULL, computer + "\x00", CLIENT_CHALLENGE)["ServerChallenge"]
        session_key = nrpc.ComputeSessionKeyAES(None, CLIENT_CHALLENGE, server_challenge, sharedSecretHash=nt_hash)
        client_credential = nrpc.ComputeNetlogonCredentialAES(CLIENT_CHALLENGE, session_key)
        response = nrpc.hNetrServerAuthenticate3(dce, NULL, sam + "\x00", channel_type, computer + "\x00", client_credential, NETLOGON_FLAGS_AES)
    except DCERPCException as exc:
        msg = f"secure channel bootstrap failed: {exc}"
        raise MethodUnavailable(msg) from exc
    if response["ServerCredential"] != nrpc.ComputeNetlogonCredentialAES(server_challenge, session_key):
        msg = "server credential mismatch: the current machine secret is wrong"
        raise MethodUnavailable(msg)

    # Upgrade to a sealed channel: set credentials and auth, alter-bind to send NL_AUTH_MESSAGE, set key.
    dce.set_credentials(sam, "IGNORED", netbios_domain)
    dce.set_auth_type(RPC_C_AUTHN_NETLOGON)
    dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.set_aes(True)
    dce.bind(MSRPC_UUID_NRPC, alter=1)
    dce.set_session_key(session_key)
    return dce, session_key, client_credential


def change_aes(target: Target, netbios_domain: str, account: str, kind: AccountKind, new_password: str, old: Secret) -> int:
    """NetrServerPasswordSet2 (opnum 30): write a new machine/trust password as an AES NL_TRUST_PASSWORD."""
    channel_type = channel_type_for(kind)
    dce, session_key, client_credential = open_secure_channel(target, netbios_domain, account, channel_type, old)
    sam = _sam_account(account)
    try:
        blob = crypto.aes_cfb8_encrypt(session_key, crypto.build_nl_trust_password(new_password))
        authenticator = nrpc.ComputeNetlogonAuthenticatorAES(client_credential, session_key)
        nrpc.hNetrServerPasswordSet2(dce, NULL, sam + "\x00", channel_type, sam[:-1] + "\x00", authenticator, blob)
    except DCERPCException as exc:
        return _fault_status(exc)
    finally:
        _safe_disconnect(dce)
    return STATUS_SUCCESS


def change_des(target: Target, netbios_domain: str, account: str, kind: AccountKind, new_password: str, old: Secret) -> int:
    """NetrServerPasswordSet (opnum 6): write a new machine/trust password as a DES-encrypted NT OWF."""
    channel_type = channel_type_for(kind)
    dce, session_key, client_credential = open_secure_channel(target, netbios_domain, account, channel_type, old)
    sam = _sam_account(account)
    try:
        request = ndr.NetrServerPasswordSet()
        request["PrimaryName"] = NULL
        request["AccountName"] = sam + "\x00"
        request["SecureChannelType"] = channel_type
        request["ComputerName"] = sam[:-1] + "\x00"
        request["Authenticator"] = nrpc.ComputeNetlogonAuthenticatorAES(client_credential, session_key)
        owf = ENCRYPTED_NT_OWF_PASSWORD()
        owf["Data"] = crypto.des_owf_encrypt(crypto.nt_owf(new_password), session_key)
        request["UasNewPassword"] = owf
        dce.request(request)
    except DCERPCException as exc:
        return _fault_status(exc)
    finally:
        _safe_disconnect(dce)
    return STATUS_SUCCESS


def _fault_status(exc: DCERPCException) -> int:
    """Extract the NTSTATUS from a Netlogon RPC fault, or signal that the method is unavailable."""
    getter = getattr(exc, "get_error_code", None)
    if callable(getter):
        return int(getter()) & 0xFFFFFFFF
    raise MethodUnavailable(str(exc)) from exc


def _safe_disconnect(dce: DCERPC_v5) -> None:
    """Disconnect a Netlogon channel, ignoring teardown errors."""
    with contextlib.suppress(DCERPCException):
        dce.disconnect()
