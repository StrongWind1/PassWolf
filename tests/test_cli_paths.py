"""CLI dispatch, AUTO fallback, guard, and error-path coverage without a live host.

The live matrices exercise the happy paths against real domain controllers; these tests pin the
deterministic branches that do not need a network: the AUTO method-selection fallbacks, the transport and
credential guards, the argument-error exit codes, the pass-the-hash refusals, and the output formatter.
Channels and method calls are monkeypatched so the dispatch logic runs against fakes.
"""

import json
from types import SimpleNamespace

import pytest
from impacket.dcerpc.v5.nrpc import NETLOGON_SECURE_CHANNEL_TYPE
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError

from passwolf import change as change_cli
from passwolf import crypto, netlogon, samr
from passwolf import reset as reset_cli
from passwolf.change import ChangeConfig
from passwolf.console import Outcome, render
from passwolf.constants import (
    OPNUM_SAMR_SET_INFORMATION_USER,
    OPNUM_SAMR_SET_INFORMATION_USER2,
    USER_INTERNAL4_INFORMATION,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)
from passwolf.errors import MethodUnavailable
from passwolf.model import (
    AccountKind,
    ChangeMethod,
    OutputFormat,
    ResetMethod,
    Secret,
    Target,
    TransportKind,
)
from passwolf.reset import ResetConfig
from passwolf.transport import BindIdentity

EMPTY_NT_HEX = "31d6cfe0d16ae931b73c59d7e0c089c0"
_NEW = "New1!xQ"


def _raise_unavailable(*_args, **_kwargs):
    msg = "forced unavailable"
    raise MethodUnavailable(msg)


def _change_cfg(*, method=ChangeMethod.AUTO, account=AccountKind.USER, old=None, new="New1!xQ"):
    target = Target(domain="SNOW", user="u", dc="dc")
    secret = old if old is not None else Secret(password="Old1!xQ")
    bind = BindIdentity(user="u", domain="SNOW", password="Old1!xQ")
    return ChangeConfig(target=target, new_password=new, old=secret, account=account, method=method, transport=TransportKind.SMB, bind=bind, netbios="SNOW", use_ldaps=False, output=OutputFormat.TEXT)


def _reset_cfg(*, method=ResetMethod.AUTO, new_password=_NEW, new_nt_hash=None, new_lm_hash=None, reset_opnum=None, reset_info_class=None):
    target = Target(domain="SNOW", user="u", dc="dc")
    bind = BindIdentity(user="Administrator", domain="SNOW", password="Admin1!")
    return ResetConfig(target=target, new_password=new_password, new_nt_hash=new_nt_hash, new_lm_hash=new_lm_hash, method=method, transport=TransportKind.SMB, bind=bind, expire=False, use_ldaps=False, output=OutputFormat.TEXT, reset_opnum=reset_opnum, reset_info_class=reset_info_class)


# --- Legacy-method UX warnings ---
def test_legacy_methods_warn(caplog):
    # Each discouraged legacy method emits an up-front warning naming its pitfalls; the modern ones stay quiet.
    for method in (ChangeMethod.SAMR_OEM, ChangeMethod.RAP, ChangeMethod.RAP_OEM):
        caplog.clear()
        with caplog.at_level("WARNING", logger="pwchange"):
            change_cli._warn_if_legacy(method)
        assert any(method.value in rec.message and ("legacy" in rec.message.lower() or "obsolete" in rec.message.lower()) for rec in caplog.records)
    caplog.clear()
    with caplog.at_level("WARNING", logger="pwchange"):
        change_cli._warn_if_legacy(ChangeMethod.SAMR_AES)
    assert not caplog.records


# --- Change AUTO selection fallbacks ([MS-SAMR] 3.2.2.4 preflight + fault fallback) ---
def test_auto_change_supports_aes_false_uses_rc4(monkeypatch):
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: False)
    monkeypatch.setattr("passwolf.samr.change_rc4", lambda _dce, _u, _n, _o: 0)
    method, status, _ = change_cli._auto_samr_change(object(), _change_cfg())
    assert method is ChangeMethod.SAMR_RC4
    assert status == 0


def test_auto_change_aes_fault_falls_back_to_rc4(monkeypatch):
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: None)
    monkeypatch.setattr("passwolf.samr.change_aes", _raise_unavailable)
    monkeypatch.setattr("passwolf.samr.change_rc4", lambda _dce, _u, _n, _o: 0)
    method, status, _ = change_cli._auto_samr_change(object(), _change_cfg())
    assert method is ChangeMethod.SAMR_RC4
    assert status == 0


def test_auto_change_not_supported_falls_back_to_rc4(monkeypatch):
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: True)
    monkeypatch.setattr("passwolf.samr.change_aes", lambda *_a, **_k: 0xC00000BB)  # STATUS_NOT_SUPPORTED
    monkeypatch.setattr("passwolf.samr.change_rc4", lambda _dce, _u, _n, _o: 0)
    method, status, _ = change_cli._auto_samr_change(object(), _change_cfg())
    assert method is ChangeMethod.SAMR_RC4
    assert status == 0


def test_auto_change_aes_available_uses_aes(monkeypatch):
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: True)
    monkeypatch.setattr("passwolf.samr.change_aes", lambda *_a, **_k: 0)
    method, status, _ = change_cli._auto_samr_change(object(), _change_cfg())
    assert method is ChangeMethod.SAMR_AES
    assert status == 0


def test_netlogon_auto_prefers_aes(monkeypatch):
    # The native secure-channel AES change wins when it is available.
    monkeypatch.setattr("passwolf.netlogon.change_aes", lambda *_a, **_k: 0)
    method, status, _ = change_cli._run_netlogon_change(_change_cfg(method=ChangeMethod.AUTO, account=AccountKind.MACHINE))
    assert method is ChangeMethod.NETLOGON_AES
    assert status == 0


def test_netlogon_auto_machine_falls_back_to_samr_aes(monkeypatch):
    # When netlogon-aes is unavailable, a machine account falls to the SAMR AES cleartext change (which
    # regenerates all Kerberos keys) before ever touching the DES variants.
    monkeypatch.setattr("passwolf.netlogon.change_aes", _raise_unavailable)
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.change.open_channel", lambda *_a, **_k: channel)
    monkeypatch.setattr("passwolf.samr.change_aes", lambda *_a, **_k: 0)
    method, status, _ = change_cli._run_netlogon_change(_change_cfg(method=ChangeMethod.AUTO, account=AccountKind.MACHINE))
    assert method is ChangeMethod.SAMR_AES
    assert status == 0


def test_netlogon_auto_machine_falls_to_des_when_samr_unavailable(monkeypatch):
    # Oldest DCs: netlogon-aes and the SAMR AES change are both unavailable, so netlogon-des is the floor.
    monkeypatch.setattr("passwolf.netlogon.change_aes", _raise_unavailable)
    monkeypatch.setattr("passwolf.change._open_samr_channel", _raise_unavailable)
    monkeypatch.setattr("passwolf.netlogon.change_des", lambda *_a, **_k: 0)
    method, status, _ = change_cli._run_netlogon_change(_change_cfg(method=ChangeMethod.AUTO, account=AccountKind.MACHINE))
    assert method is ChangeMethod.NETLOGON_DES
    assert status == 0


def test_netlogon_auto_trust_skips_samr_aes(monkeypatch):
    # Trust accounts are not SAMR-changeable, so the trust ladder is netlogon-aes -> netlogon-des only.
    monkeypatch.setattr("passwolf.netlogon.change_aes", _raise_unavailable)
    monkeypatch.setattr("passwolf.change._open_samr_channel", lambda *_a, **_k: pytest.fail("trust must not attempt the SAMR change"))
    monkeypatch.setattr("passwolf.netlogon.change_des", lambda *_a, **_k: 0)
    method, status, _ = change_cli._run_netlogon_change(_change_cfg(method=ChangeMethod.AUTO, account=AccountKind.TRUST))
    assert method is ChangeMethod.NETLOGON_DES
    assert status == 0


def test_channel_type_for_machine_and_trust():
    # A trust is addressed by its flat NetBIOS name plus '$' (the _sam_account form), which the server
    # accepts only over TrustedDomainSecureChannel; pairing the flat name with the DNS-domain channel
    # (TrustedDnsDomainSecureChannel) draws STATUS_NO_TRUST_SAM_ACCOUNT (confirmed live).
    assert netlogon.channel_type_for(AccountKind.MACHINE) == NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel
    assert netlogon.channel_type_for(AccountKind.TRUST) == NETLOGON_SECURE_CHANNEL_TYPE.TrustedDomainSecureChannel


def test_change_account_trust_routes_to_netlogon_with_trust_kind(monkeypatch):
    seen = {}

    def fake_aes(_target, _netbios, _account, kind, _new, _old):
        seen["kind"] = kind
        return 0

    monkeypatch.setattr("passwolf.netlogon.change_aes", fake_aes)
    outcome = change_cli._run_change(_change_cfg(method=ChangeMethod.NETLOGON_AES, account=AccountKind.TRUST))
    assert outcome.method == "netlogon-aes"
    assert seen["kind"] is AccountKind.TRUST


# --- Reset AUTO ladder + routing ---
def test_auto_reset_supports_aes_false_uses_rc4(monkeypatch):
    # The SAMR tail of AUTO skips AES when the DC does not advertise it and takes the RC4 reset.
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: False)
    monkeypatch.setattr("passwolf.samr.reset_rc4", lambda _dce, _uh, _sk, _pw, **_kw: 0)
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16)
    method, status = reset_cli._auto_samr_ladder(channel, _reset_cfg(), object(), [])
    assert method == ResetMethod.SAMR_RC4.value
    assert status == 0


def test_auto_reset_aes_fault_falls_back_to_rc4(monkeypatch):
    # An AES reset that raises MethodUnavailable is recorded and the ladder falls through to RC4.
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: True)
    monkeypatch.setattr("passwolf.samr.reset_aes", _raise_unavailable)
    monkeypatch.setattr("passwolf.samr.reset_rc4", lambda _dce, _uh, _sk, _pw, **_kw: 0)
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16)
    method, status = reset_cli._auto_samr_ladder(channel, _reset_cfg(), object(), [])
    assert method == ResetMethod.SAMR_RC4.value
    assert status == 0


def test_auto_reset_prefers_kpasswd(monkeypatch):
    # With a cleartext password, AUTO tries the Kerberos set first and stops on its success.
    monkeypatch.setattr("passwolf.kpasswd.reset", lambda *_a, **_k: 0)
    method, status = reset_cli._run_auto_reset(_reset_cfg())
    assert method == ResetMethod.KPASSWD.value
    assert status == 0


def test_auto_reset_falls_through_kerberos_ldap_to_samr(monkeypatch):
    # When kpasswd and both LDAP rungs are unavailable, AUTO lands on the SAMR AES reset.
    order = []
    monkeypatch.setattr("passwolf.kpasswd.reset", _raise_unavailable)
    monkeypatch.setattr("passwolf.ldap.reset", _raise_unavailable)
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.reset.open_channel", lambda *_a, **_k: channel)
    monkeypatch.setattr("passwolf.samr.open_user_handle", lambda _dce, _u: (object(), 0))
    monkeypatch.setattr("passwolf.samr.supports_aes", lambda _dce: True)

    def fake_aes(*_a, **_k):
        order.append("aes")
        return 0

    monkeypatch.setattr("passwolf.samr.reset_aes", fake_aes)
    method, status = reset_cli._run_auto_reset(_reset_cfg())
    assert method == ResetMethod.SAMR_AES.value
    assert status == 0
    assert order == ["aes"]


def test_reset_auto_routes_to_hash_when_nt_supplied(monkeypatch):
    # A hash-only secret skips every cleartext rung and drops straight to the SAMR set-hash reset.
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.reset.open_channel", lambda *_a, **_k: channel)
    monkeypatch.setattr("passwolf.samr.open_user_handle", lambda _dce, _u: (object(), 0))
    seen = {}

    def fake_hash(_dce, _uh, _sk, _nt, _lm, *, expire):
        seen["hash"] = True
        return 0

    monkeypatch.setattr("passwolf.samr.reset_hash", fake_hash)
    method, status = reset_cli._run_auto_reset(_reset_cfg(method=ResetMethod.AUTO, new_password=None, new_nt_hash=b"\x11" * 16))
    assert method == ResetMethod.SAMR_HASH.value
    assert status == 0
    assert seen.get("hash")


# --- Reset transport / session-key guard ---
def test_dsrm_requires_smb_session_key(monkeypatch):
    channel = SimpleNamespace(dce=object(), session_key=None, close=lambda: None)
    monkeypatch.setattr("passwolf.reset.open_channel", lambda *_a, **_k: channel)
    with pytest.raises(MethodUnavailable):
        reset_cli._run_dsrm_reset(_reset_cfg(method=ResetMethod.DSRM))


def test_dsrm_flag_selects_dsrm_method():
    # The dedicated --dsrm flag is its own selector; it overrides --method and resolves to the DSRM reset.
    cfg = reset_cli._build_config(reset_cli._build_parser().parse_args(["--target-domain", "SNOW", "--target-user", "ignored", "--dc", "dc", "--auth-as-user", "Administrator", "--auth-as-password", "Admin1!", "--target-new-password", "NewDsrm1!xQ", "--dsrm"]))
    assert cfg.method is ResetMethod.DSRM


# --- Advanced opnum + USER_INFORMATION_CLASS selection ---
def test_reset_advanced_info_class_routes_to_set_information(monkeypatch):
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.reset.open_channel", lambda *_a, **_k: channel)
    monkeypatch.setattr("passwolf.samr.open_user_handle", lambda _dce, _u: (object(), 0))
    seen = {}

    def fake_set_info(_dce, _uh, _sk, *, opnum, info_class, new_password, nt_hash, lm_hash, expire):
        seen.update(opnum=opnum, info_class=info_class, new_password=new_password)
        return 0

    monkeypatch.setattr("passwolf.samr.reset_set_information", fake_set_info)
    method, status = reset_cli._run_samr_reset(_reset_cfg(reset_info_class=USER_INTERNAL7_INFORMATION, reset_opnum=OPNUM_SAMR_SET_INFORMATION_USER))
    assert status == 0
    assert seen == {"opnum": OPNUM_SAMR_SET_INFORMATION_USER, "info_class": USER_INTERNAL7_INFORMATION, "new_password": _NEW}
    assert method == "samr-internal7-op37"


def test_reset_advanced_info_class_defaults_to_opnum_58(monkeypatch):
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.reset.open_channel", lambda *_a, **_k: channel)
    monkeypatch.setattr("passwolf.samr.open_user_handle", lambda _dce, _u: (object(), 0))
    monkeypatch.setattr("passwolf.samr.reset_set_information", lambda *_a, **kw: 0 if kw["opnum"] == OPNUM_SAMR_SET_INFORMATION_USER2 else 1)
    method, status = reset_cli._run_samr_reset(_reset_cfg(reset_info_class=USER_INTERNAL8_INFORMATION))
    assert status == 0
    assert method == "samr-internal8-op58"


def test_reset_info_class_overrides_method():
    cfg = reset_cli._build_config(reset_cli._build_parser().parse_args([*_RESET_TARGET, "--auth-as-user", "Administrator", "--auth-as-password", "Admin1!", "--target-new-password", "x", "--method", "samr-aes", "--reset-info-class", "internal4"]))
    assert cfg.reset_info_class == USER_INTERNAL4_INFORMATION


def test_reset_opnum_without_info_class_exits_2():
    assert reset_cli.main([*_RESET_TARGET, "--auth-as-user", "Administrator", "--auth-as-password", "Admin1!", "--target-new-password", "x", "--reset-opnum", "37"]) == 2


def test_reset_dsrm_and_info_class_conflict_exits_2():
    assert reset_cli.main([*_RESET_TARGET, "--auth-as-user", "Administrator", "--auth-as-password", "Admin1!", "--target-new-password", "x", "--reset-info-class", "internal7", "--dsrm"]) == 2


def test_reset_method_choices_exclude_dsrm():
    # dsrm is reached via the --dsrm flag, not the standard --method list, so it is rejected as a --method;
    # UserInternal8 (the former samr-aes-all) is reached via --reset-info-class internal8, tested above.
    parser = reset_cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([*_RESET_TARGET, "--auth-as-user", "a", "--target-new-password", "x", "--method", "dsrm"])


def test_reset_require_password_guard():
    with pytest.raises(MethodUnavailable):
        _reset_cfg(new_password=None).require_password()


def test_reset_require_nt_hash_guard():
    # Neither a hash nor a cleartext password: the set-hash path has nothing to set.
    with pytest.raises(MethodUnavailable):
        _reset_cfg(new_password=None, new_nt_hash=None).require_nt_hash()


def test_reset_require_nt_hash_derives_from_password():
    # A cleartext password is hashed locally into its NT OWF for the set-hash path.
    assert _reset_cfg(new_password="NewPass1!", new_nt_hash=None).require_nt_hash() == crypto.nt_owf("NewPass1!")


# --- Interactive prompting for passwords omitted on the command line ---
_CHANGE_TARGET = ["--target-domain", "SNOW", "--target-user", "u", "--dc", "dc"]
_RESET_TARGET = ["--target-domain", "SNOW", "--target-user", "u", "--dc", "dc"]


def test_change_prompts_for_omitted_passwords(monkeypatch):
    # With no old credential and no new password on the command line, both are read interactively.
    monkeypatch.setattr("passwolf.change.prompt_password", lambda label: f"P:{label}")
    cfg = change_cli._build_config(change_cli._build_parser().parse_args(_CHANGE_TARGET))
    assert cfg.new_password.startswith("P:")
    assert cfg.old.password.startswith("P:")


def test_change_old_hash_skips_old_password_prompt(monkeypatch):
    # A pass-the-hash change supplies the hash, so only the new password is prompted, never the old.
    monkeypatch.setattr("passwolf.change.prompt_password", lambda label: f"P:{label}")
    cfg = change_cli._build_config(change_cli._build_parser().parse_args([*_CHANGE_TARGET, "--target-old-hash", EMPTY_NT_HEX]))
    assert cfg.old.password is None
    assert cfg.new_password.startswith("P:")


def test_reset_prompts_for_omitted_passwords(monkeypatch):
    # The new password and the privileged caller's password are both read interactively when omitted.
    monkeypatch.setattr("passwolf.reset.prompt_password", lambda label: f"P:{label}")
    cfg = reset_cli._build_config(reset_cli._build_parser().parse_args([*_RESET_TARGET, "--auth-as-user", "Administrator"]))
    assert cfg.new_password.startswith("P:")
    assert cfg.bind.password.startswith("P:")


def _never_prompt(_label):
    raise AssertionError("a Kerberos bind must not prompt for a password")


# --- Kerberos (-k) binds the auth-as principal with a ticket, suppressing the NTLM password prompt ---
def test_change_kerberos_sets_bind_and_skips_prompt(monkeypatch):
    monkeypatch.setattr("passwolf.change.prompt_password", _never_prompt)
    # Old hash and new password are supplied, so the only credential left is the bind, which -k satisfies.
    cfg = change_cli._build_config(change_cli._build_parser().parse_args([*_CHANGE_TARGET, "--target-new-password", "x", "--target-old-hash", EMPTY_NT_HEX, "--auth-as-user", "svc", "-k"]))
    assert cfg.bind.use_kerberos is True
    assert cfg.bind.user == "svc"


def test_reset_kerberos_sets_bind_and_skips_prompt(monkeypatch):
    monkeypatch.setattr("passwolf.reset.prompt_password", _never_prompt)
    cfg = reset_cli._build_config(reset_cli._build_parser().parse_args([*_RESET_TARGET, "--target-new-password", "x", "--auth-as-user", "Administrator", "-k"]))
    assert cfg.bind.use_kerberos is True


def test_change_without_kerberos_leaves_bind_ntlm(monkeypatch):
    monkeypatch.setattr("passwolf.change.prompt_password", lambda label: f"P:{label}")
    cfg = change_cli._build_config(change_cli._build_parser().parse_args([*_CHANGE_TARGET, "--target-new-password", "x", "--target-old-hash", EMPTY_NT_HEX, "--auth-as-user", "svc"]))
    assert cfg.bind.use_kerberos is False


# --- Gap 1: expired-password null-session change retry ([MS-SAMR] 3.1.5.10.3) ---
def test_open_samr_channel_retries_null_session_on_expired(monkeypatch):
    # The authenticated bind fails STATUS_PASSWORD_MUST_CHANGE; a buffer-based change retries over a null
    # session (empty bind identity) and proceeds.
    seen = []
    fake_channel = SimpleNamespace(dce=object(), close=lambda: None)

    def fake_open(_target, identity, *_a, **_k):
        seen.append(identity)
        if len(seen) == 1:
            raise SessionError(0xC0000224)  # STATUS_PASSWORD_MUST_CHANGE
        return fake_channel

    monkeypatch.setattr("passwolf.change.open_channel", fake_open)
    channel = change_cli._open_samr_channel(_change_cfg(method=ChangeMethod.SAMR_RC4))
    assert channel is fake_channel
    assert seen[0].user == "u"  # first attempt: authenticated as the target
    assert seen[1].user == ""  # retry: null session


def test_open_samr_channel_expired_des_is_unavailable(monkeypatch):
    # The DES change needs a user handle a null session is denied, so an expired account cannot use it.
    monkeypatch.setattr("passwolf.change.open_channel", lambda *_a, **_k: (_ for _ in ()).throw(SessionError(0xC0000071)))
    with pytest.raises(MethodUnavailable):
        change_cli._open_samr_channel(_change_cfg(method=ChangeMethod.SAMR_DES))


def test_open_samr_channel_other_bind_error_propagates(monkeypatch):
    # A non-expiry bind failure (wrong password) is not retried over a null session.
    monkeypatch.setattr("passwolf.change.open_channel", lambda *_a, **_k: (_ for _ in ()).throw(SessionError(0xC000006A)))
    with pytest.raises(SessionError):
        change_cli._open_samr_channel(_change_cfg(method=ChangeMethod.SAMR_RC4))


# --- Gap 2: set new password by NT hash on a change (DES, opnum 38) ---
def test_change_new_hash_pins_samr_des():
    cfg = change_cli._build_config(change_cli._build_parser().parse_args([*_CHANGE_TARGET, "--target-old-password", "Old1!", "--target-new-hash", EMPTY_NT_HEX]))
    assert cfg.method is ChangeMethod.SAMR_DES
    assert cfg.new_password is None
    assert cfg.new_nt_hash == bytes.fromhex(EMPTY_NT_HEX)


def test_change_new_hash_conflicting_method_exits_2():
    assert change_cli.main([*_CHANGE_TARGET, "--target-old-password", "Old1!", "--target-new-hash", EMPTY_NT_HEX, "--method", "samr-rc4"]) == 2


def test_change_new_password_and_hash_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        change_cli._build_parser().parse_args([*_CHANGE_TARGET, "--target-new-password", "x", "--target-new-hash", EMPTY_NT_HEX])


# --- Pass-the-hash refusals that raise before any connection ---
def test_change_rap_pass_the_hash_exits_1():
    assert change_cli.main([*_CHANGE_TARGET, "--target-new-password", "x", "--method", "rap", "--target-old-hash", EMPTY_NT_HEX]) == 1


def test_change_rap_oem_pass_the_hash_exits_1():
    assert change_cli.main([*_CHANGE_TARGET, "--target-new-password", "x", "--method", "rap-oem", "--target-old-hash", EMPTY_NT_HEX]) == 1


def test_change_samr_oem_pass_the_hash_exits_1(monkeypatch):
    channel = SimpleNamespace(dce=object(), session_key=b"k" * 16, close=lambda: None)
    monkeypatch.setattr("passwolf.change.open_channel", lambda *_a, **_k: channel)
    assert change_cli.main([*_CHANGE_TARGET, "--target-new-password", "x", "--method", "samr-oem", "--target-old-hash", EMPTY_NT_HEX]) == 1


# --- supports_aes preflight degradation (returns None, never raises) ---
def test_supports_aes_none_on_fault():
    class _D:
        def request(self, _req):
            msg = "boom"
            raise DCERPCException(msg)

    assert samr.supports_aes(_D()) is None


def test_supports_aes_none_on_malformed_response():
    class _D:
        def request(self, _req):
            return {}  # missing OutRevisionInfo -> KeyError -> None

    assert samr.supports_aes(_D()) is None


# --- Output formatter (json) ---
def test_render_json_shape():
    outcome = Outcome(operation="change", method="samr-aes", target="SNOW\\u", dc="dc", status=0, extra={"k": "v"})
    payload = json.loads(render(outcome, OutputFormat.JSON))
    assert payload["operation"] == "change"
    assert payload["success"] is True
    assert payload["status_name"] == "STATUS_SUCCESS"
    assert payload["extra"] == {"k": "v"}


def test_render_json_failure_status():
    outcome = Outcome(operation="reset", method="samr-aes", target="SNOW\\u", dc="dc", status=0xC000006A)
    payload = json.loads(render(outcome, OutputFormat.JSON))
    assert payload["success"] is False
    assert payload["status"] == "0xC000006A"


# --- Model guards ---
def test_secret_require_password_rejects_hash_only():
    with pytest.raises(ValueError, match="cleartext"):
        Secret(nt_hash=b"\x11" * 16).require_password()


# --- Crypto buffer length guard ---
def test_des_owf_encrypt_rejects_wrong_length():
    with pytest.raises(ValueError, match="16 bytes"):
        crypto.des_owf_encrypt(b"\x00" * 15, b"\x11" * 16)
