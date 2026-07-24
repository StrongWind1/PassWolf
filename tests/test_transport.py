# SPDX-License-Identifier: Apache-2.0
"""Transport-layer Kerberos wiring, exercised against fakes so no live KDC or DC is needed.

The bind logic must turn the -k flag into impacket's Kerberos path: the shared kerberosLogin keyword set
(used by the LDAP and SYSVOL binds) and the SMBTransport doKerberos/kdcHost plumbing. These pin both so a
regression in the credential plumbing is caught without a network.
"""

from types import SimpleNamespace

from passwolf.model import Target, TransportKind
from passwolf.transport import BindIdentity, kerberos_login_args, open_channel


def test_kerberos_login_args_uses_cache_and_credentials():
    # useCache=True is what makes impacket read KRB5CCNAME; the password/NT hash ride along as the
    # fallback used to fetch a fresh TGT when the cache is empty.
    identity = BindIdentity(user="svc", domain="CORP", password="pw", nt_hash=b"\x11" * 16, use_kerberos=True)
    kwargs = kerberos_login_args(identity, "dc01.corp.local")
    assert kwargs["useCache"] is True
    assert kwargs["user"] == "svc"
    assert kwargs["domain"] == "CORP"
    assert kwargs["kdcHost"] == "dc01.corp.local"
    assert kwargs["nthash"] == "11" * 16


class _FakeDCE:
    """A no-op DCE/RPC handle so open_channel can run its bind sequence against a fake."""

    def connect(self):
        pass

    def bind(self, _interface_uuid):
        pass

    def set_auth_level(self, _level):
        pass


def test_open_channel_smb_kerberos_enables_dokerberos(monkeypatch):
    # Over SMB the kerberos handshake is impacket's job; open_channel only has to flip doKerberos and pass
    # the KDC, so assert those reach the SMBTransport constructor.
    captured: dict[str, object] = {}

    class _FakeSMB:
        def __init__(self, *_args, **kwargs):
            captured.update(kwargs)

        def get_dce_rpc(self):
            return _FakeDCE()

        def get_smb_connection(self):
            return SimpleNamespace(getSessionKey=lambda: b"k" * 16)

    monkeypatch.setattr("passwolf.transport.transport.SMBTransport", _FakeSMB)
    identity = BindIdentity(user="svc", domain="CORP", password="pw", use_kerberos=True)
    open_channel(Target(domain="CORP", user="u", dc="dc01.corp.local"), identity, b"\x00" * 16, r"\pipe\samr", TransportKind.SMB)
    assert captured["doKerberos"] is True
    assert captured["kdcHost"] == "dc01.corp.local"


def test_open_channel_smb_ntlm_leaves_dokerberos_off(monkeypatch):
    # Without -k the SMB bind stays on NTLM (doKerberos False), so the default path is unchanged.
    captured: dict[str, object] = {}

    class _FakeSMB:
        def __init__(self, *_args, **kwargs):
            captured.update(kwargs)

        def get_dce_rpc(self):
            return _FakeDCE()

        def get_smb_connection(self):
            return SimpleNamespace(getSessionKey=lambda: b"k" * 16)

    monkeypatch.setattr("passwolf.transport.transport.SMBTransport", _FakeSMB)
    identity = BindIdentity(user="svc", domain="CORP", password="pw")
    open_channel(Target(domain="CORP", user="u", dc="dc01.corp.local"), identity, b"\x00" * 16, r"\pipe\samr", TransportKind.SMB)
    assert captured["doKerberos"] is False
