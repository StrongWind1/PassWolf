"""DCE/RPC transport binding for SAMR and LSA.

Both interfaces can ride an SMB named pipe (ncacn_np) or direct TCP (ncacn_ip_tcp). The reset paths
need the SMB session key as their content-encryption key, which only exists over the named pipe, so
the channel records it when present. Netlogon has its own challenge/seal handshake and lives in
``methods/netlogon.py`` rather than here.
"""

from __future__ import annotations

import binascii
import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import epm, transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.krb5.ccache import CCache

from .model import TransportKind

if TYPE_CHECKING:
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5

    from .model import Secret, Target

SMB_PORT = 445


@dataclass(frozen=True)
class BindIdentity:
    """The principal used to authenticate the RPC bind (not necessarily the account being changed).

    When ``use_kerberos`` is set the bind authenticates with Kerberos: the ticket cache named by
    ``KRB5CCNAME`` is used when present, otherwise a TGT is requested from the KDC with the password or NT
    hash. NTLM (password or pass-the-hash) is used otherwise.
    """

    user: str
    domain: str
    password: str = ""
    nt_hash: bytes | None = None
    use_kerberos: bool = False

    @classmethod
    def from_secret(cls, user: str, domain: str, secret: Secret) -> BindIdentity:
        """Build a bind identity from an account name and a :class:`Secret` (cleartext or NT hash)."""
        return cls(user=user, domain=domain, password=secret.password or "", nt_hash=secret.nt_hash)


def kerberos_login_args(identity: BindIdentity, kdc_host: str) -> dict[str, object]:
    """Build the keyword arguments shared by every impacket ``kerberosLogin`` (LDAP and SMB).

    The connection-level ``kerberosLogin`` reads ``KRB5CCNAME`` itself (``useCache=True``), so the cache is
    consulted first and the password/NT hash are only used to request a fresh TGT when no ticket is found.
    """
    return {
        "user": identity.user,
        "password": identity.password,
        "domain": identity.domain,
        "nthash": _nt_hex(identity.nt_hash),
        "aesKey": "",
        "kdcHost": kdc_host,
        "useCache": True,
    }


@dataclass
class Channel:
    """A bound DCE/RPC channel and the SMB session key when the transport provides one."""

    dce: DCERPC_v5
    session_key: bytes | None

    def close(self) -> None:
        """Disconnect the underlying transport, ignoring teardown errors."""
        with contextlib.suppress(DCERPCException):
            self.dce.disconnect()


def _nt_hex(nt_hash: bytes | None) -> str:
    """Render an NT hash as the hex string impacket's credential setters expect (empty when absent)."""
    return binascii.hexlify(nt_hash).decode() if nt_hash else ""


def open_channel(target: Target, identity: BindIdentity, interface_uuid: bytes, pipe: str, kind: TransportKind, *, seal: bool = False) -> Channel:
    """Bind ``interface_uuid`` over the chosen transport and return a :class:`Channel`.

    Over SMB the SMB session key is captured for the reset paths; over TCP there is no session key, so
    the reset cleartext info levels are unavailable and the caller must surface that clearly.
    """
    nt_hex = _nt_hex(identity.nt_hash)
    if kind is TransportKind.TCP:
        binding = epm.hept_map(target.dc, interface_uuid, protocol="ncacn_ip_tcp")
        rpc = transport.DCERPCTransportFactory(binding)
        if identity.use_kerberos:
            # ncacn_ip_tcp does not consult KRB5CCNAME on its own, so resolve the ticket here and hand the
            # TGT/TGS to the bind; the password or NT hash is kept as the fallback when the cache is empty.
            cache_domain, cache_user, tgt, tgs = CCache.parseFile(identity.domain, identity.user)
            rpc.set_credentials(cache_user, identity.password, cache_domain, "", nt_hex, "", tgt, tgs)
            rpc.set_kerberos(True, kdcHost=target.dc)
        else:
            rpc.set_credentials(identity.user, identity.password, identity.domain, "", nt_hex)
        dce = rpc.get_dce_rpc()
        dce.connect()
        if identity.use_kerberos:
            # A Kerberos bind needs an authentication level above NONE, so seal the channel.
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        elif seal:
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(interface_uuid)
        return Channel(dce=dce, session_key=None)

    # Over SMB the transport's own kerberosLogin reads KRB5CCNAME (useCache) when doKerberos is set.
    rpc = transport.SMBTransport(target.dc, SMB_PORT, pipe, username=identity.user, password=identity.password, domain=identity.domain, nthash=nt_hex, doKerberos=identity.use_kerberos, kdcHost=target.dc)
    dce = rpc.get_dce_rpc()
    dce.connect()
    session_key = rpc.get_smb_connection().getSessionKey()
    if seal:
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.bind(interface_uuid)
    return Channel(dce=dce, session_key=session_key)
