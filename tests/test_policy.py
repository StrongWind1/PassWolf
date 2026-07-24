# SPDX-License-Identifier: Apache-2.0
"""Tests for the read-only password-policy tool: conversions, wire parsing, rendering, and CLI wiring.

These run without a domain controller. The opnum-63 oracle is exercised with the same captured Server
2022 response stub as the change tool's diagnostic path, the kpasswd SOFTERROR parse is pinned against a
hand-built policy blob, and the SYSVOL template parser is fed a synthetic GptTmpl.inf.
"""

import json
import struct

import pytest
from impacket.krb5 import kpasswd as ik
from impacket.ldap.ldap import LDAPSessionError

from passwolf import console, policy, pwpolicy
from passwolf.errors import OperationFailed
from passwolf.model import OutputFormat, Secret
from passwolf.policymodel import (
    PasswordPolicy,
    PolicyReadResult,
    PsoPolicy,
    complexity_from_properties,
    decode_properties,
    reversible_from_properties,
    ticks_to_days,
    ticks_to_minutes,
)

# The opnum-63 response stub reused from the change tool's diagnostic test: a too-short rejection
# (STATUS_PASSWORD_RESTRICTION) with MinPasswordLength 7, PasswordHistoryLength 24, properties 1
# (complexity), ExtendedFailureReason 1. The success stub has both referents NULL.
DIAG_RESTRICTION_STUB = bytes.fromhex("0000020007001800010000000080a60affdeffff0000000000000000040002000100000000000000000000006c0000c0")
DIAG_SUCCESS_STUB = bytes.fromhex("000000000000000000000000")

_TICKS_PER_DAY = 86400 * 10_000_000


class _CallRecvDCE:
    """A DCE stub exposing the call()/recv() pair the opnum-63 oracle uses to dodge the status auto-raise."""

    def __init__(self, stub):
        self._stub = stub
        self.opnum = None

    def call(self, opnum, request):  # noqa: ARG002 - the request is built then discarded by the fake
        self.opnum = opnum

    def recv(self):
        return self._stub


# --- interval and property decoders ---
def test_ticks_to_days_normal_never_and_none():
    assert ticks_to_days(-42 * _TICKS_PER_DAY) == 42.0
    assert ticks_to_days(-0x8000000000000000) == float("inf")
    assert ticks_to_days(None) is None


def test_ticks_to_minutes_normal_and_never():
    assert ticks_to_minutes(-30 * 60 * 10_000_000) == 30.0
    assert ticks_to_minutes(-0x8000000000000000) == float("inf")


def test_decode_properties_splits_bits():
    assert decode_properties(0x1) == ["DOMAIN_PASSWORD_COMPLEX"]
    assert "DOMAIN_PASSWORD_STORE_CLEARTEXT" in decode_properties(0x11)
    assert decode_properties(None) == []


def test_complexity_and_reversible_from_properties():
    assert complexity_from_properties(0x1) is True
    assert complexity_from_properties(0x10) is False
    assert reversible_from_properties(0x10) is True
    assert complexity_from_properties(None) is None


# --- opnum-63 oracle (read-safe) ---
def test_samr_oracle_parses_restriction_stub():
    record, reason = policy.samr_oracle_policy(_CallRecvDCE(DIAG_RESTRICTION_STUB), "victim", Secret(password="OldPass1!"))
    assert record.min_password_length == 7
    assert record.password_history_length == 24
    assert record.complexity_enabled is True
    assert record.password_properties_raw == 0x1
    assert reason == "1"


def test_samr_oracle_raises_when_no_policy_block():
    # A success carries NULL referents, so there is no effective-policy block to read.
    with pytest.raises(OperationFailed):
        policy.samr_oracle_policy(_CallRecvDCE(DIAG_SUCCESS_STUB), "victim", Secret(password="OldPass1!"))


# --- kpasswd SOFTERROR policy blob ---
def _kpasswd_blob(min_length, history, flags, max_age_ticks, min_age_ticks):
    # [MS-?]/Rubeus layout decoded by impacket: reserved H, then minLength, history, flags as I, then
    # maxAge and minAge as Q tick counts.
    return struct.pack("!HIIIQQ", 0, min_length, history, flags, max_age_ticks, min_age_ticks)


def test_kpasswd_policy_record_from_blob():
    blob = _kpasswd_blob(7, 24, 0x1, 42 * _TICKS_PER_DAY, 1 * _TICKS_PER_DAY)
    record = policy._kpasswd_policy_record(ik._decodePasswordPolicy(blob), "alice")
    assert record.min_password_length == 7
    assert record.password_history_length == 24
    assert record.max_password_age_days == 42.0
    assert record.min_password_age_days == 1.0
    assert record.complexity_enabled is True
    assert record.reversible_encryption is False
    assert record.password_properties_raw == 0x1


def test_kpasswd_policy_never_max_age():
    blob = _kpasswd_blob(8, 0, 0x11, 0x8000000000000000, 0)
    record = policy._kpasswd_policy_record(ik._decodePasswordPolicy(blob), "alice")
    assert record.max_password_age_days == float("inf")
    assert record.reversible_encryption is True


# --- SYSVOL GptTmpl.inf parsing ---
_GPTTMPL = """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
MaximumPasswordAge = 42
MinimumPasswordAge = 1
ClearTextPassword = 0
LockoutBadCount = 5
LockoutDuration = 30
ResetLockoutCount = 30
"""


def test_parse_gpttmpl_system_access():
    gpo = policy._parse_gpttmpl(_GPTTMPL.encode("utf-16"), "{GUID}", "Default Domain Policy")
    assert gpo is not None
    assert gpo.min_password_length == 14
    assert gpo.complexity_enabled is True
    assert gpo.password_history_size == 24
    assert gpo.max_password_age_days == 42.0
    assert gpo.reversible_encryption is False
    assert gpo.lockout_threshold == 5
    assert gpo.lockout_duration_minutes == 30.0
    assert gpo.reset_lockout_minutes == 30.0


def test_parse_gpttmpl_never_max_age_and_no_policy():
    never = _GPTTMPL.replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1")
    assert policy._parse_gpttmpl(never.encode("utf-16"), "{G}", "g").max_password_age_days == float("inf")
    # A template with no [System Access] password keys contributes nothing.
    assert policy._parse_gpttmpl(b"[Unicode]\nUnicode=yes\n".decode().encode("utf-16"), "{G}", "g") is None


# --- rendering ---
def _sample_result():
    result = PolicyReadResult(target="CORP\\alice", dc="dc1")
    # A domain-default record and a PSO-scoped (per-user effective) record, so the renderer must keep them
    # apart: the kpasswd oracle is scope "PSO", the LDAP domain head is the default "domain".
    result.policies.append(PasswordPolicy(source="ldap-domain-head", min_password_length=14, password_history_length=24, complexity_enabled=True, max_password_age_days=float("inf"), password_properties_raw=0x1))
    result.policies.append(PasswordPolicy(source="kpasswd-softerror (RFC 3244, effective for alice)", scope="PSO", min_password_length=20, complexity_enabled=True))
    result.psos.append(PsoPolicy(name="VIP-PSO", precedence=10, min_password_length=20, applies_to=["CN=alice,..."]))
    result.reachability.update({"ldap-domain-head": "ok", "kpasswd": "ok", "samr-diag": "denied"})
    return result


def test_render_policy_text_uses_official_ms_labels():
    text = console.render_policy(_sample_result(), OutputFormat.TEXT)
    assert "ldap-domain-head" in text
    # the official Group Policy name with the protocol field in parentheses, and the unit in the value
    assert "Minimum password length (MinPasswordLength): 14" in text
    assert "Maximum password age (MaxPasswordAge): never" in text
    assert "PSO object: VIP-PSO" in text
    assert "samr-diag: denied" in text


def test_render_policy_text_differentiates_domain_and_pso():
    # The two scopes must render under distinct headers and the kpasswd record's larger minimum must land
    # in the PSO section, never merged into the domain default.
    text = console.render_policy(_sample_result(), OutputFormat.TEXT)
    assert "[domain password policy]" in text
    assert "[PSO (fine-grained) effective policy]" in text
    pso_index = text.index("[PSO (fine-grained) effective policy]")
    assert "Minimum password length (MinPasswordLength): 20" in text[pso_index:]


def test_render_policy_text_has_comparison_table_with_scope():
    text = console.render_policy(_sample_result(), OutputFormat.TEXT)
    assert "[methods]" in text
    header = next(line for line in text.splitlines() if line.strip().startswith("method"))
    assert "scope" in header  # the comparison table carries a scope column
    # each method row shows its scope and verdict alongside the headline values
    domain_row = next(line for line in text.splitlines() if line.strip().startswith("ldap-domain-head"))
    assert "domain" in domain_row
    assert "ok" in domain_row
    assert "14" in domain_row
    denied = next(line for line in text.splitlines() if line.strip().startswith("samr-diag"))
    assert "PSO" in denied  # falls back to the static scope map even though the method was denied
    assert "denied" in denied


def test_render_policy_json_uses_stable_machine_keys():
    payload = json.loads(console.render_policy(_sample_result(), OutputFormat.JSON))
    assert payload["target"] == "CORP\\alice"
    # JSON keeps snake_case keys and unitless values, never the official display labels or units. Each key
    # is the mechanical snake_case of its display label, so "Enforce password history" -> enforce_...
    assert payload["policies"][0]["minimum_password_length"] == "14"
    assert payload["policies"][0]["enforce_password_history"] == "24"
    assert payload["policies"][0]["scope"] == "domain"
    assert payload["policies"][0]["maximum_password_age"] == "never"
    # the kpasswd oracle record is carried in policies tagged PSO, not in a separate user-view key
    assert any(p["scope"] == "PSO" for p in payload["policies"])
    assert payload["reachability"]["samr-diag"] == "denied"


# --- CLI config resolution ---
def _config(argv):
    return pwpolicy._build_config(pwpolicy._build_parser().parse_args(argv))


def test_build_config_anonymous_runs_all_methods():
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--anonymous"])
    assert cfg.anonymous is True
    assert cfg.bind.user == ""
    assert cfg.target_user == ""
    assert cfg.methods == pwpolicy._ALL_METHODS


def test_build_config_auth_is_only_auth_as():
    # Authentication comes solely from the --auth-as-* flags; there is no separate subject credential.
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--auth-as-user", "admin", "--auth-as-password", "Admin1!"])
    assert cfg.bind.user == "admin"
    assert cfg.bind.password == "Admin1!"
    assert cfg.bind.domain == "corp.local"
    # --target-user defaults to the authenticated principal, so an authenticated run reads its own policy.
    assert cfg.target_user == "admin"
    assert cfg.label == "corp.local\\admin"


def test_build_config_dc_defaults_to_target_domain():
    # --dc is optional and falls back to the domain name when omitted.
    cfg = _config(["--target-domain", "corp.local", "--anonymous"])
    assert cfg.target.dc == "corp.local"


def test_build_config_prompts_for_omitted_password(monkeypatch):
    # A named principal with no password and no hash is prompted for the password interactively.
    monkeypatch.setattr(pwpolicy, "prompt_password", lambda label: f"P:{label}")
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--auth-as-user", "admin"])
    assert cfg.bind.password.startswith("P:")


def test_build_config_kerberos_skips_prompt_and_sets_bind(monkeypatch):
    # -k binds with a ticket, so no password is read interactively and the bind is flagged for Kerberos.
    monkeypatch.setattr(pwpolicy, "prompt_password", lambda label: pytest.fail("Kerberos must not prompt"))
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--auth-as-user", "admin", "-k"])
    assert cfg.bind.use_kerberos is True


def test_build_config_target_user_for_pso():
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--auth-as-user", "admin", "--auth-as-password", "Admin1!", "--target-user", "alice", "--method", "samr-query"])
    assert cfg.methods == ("samr-query",)
    assert cfg.bind.user == "admin"
    assert cfg.target_user == "alice"
    assert cfg.label == "corp.local\\alice"


def test_build_config_requires_principal_without_anonymous():
    # With no --auth-as-user and no --anonymous there is no way to bind, so config resolution must reject it.
    with pytest.raises(ValueError, match="auth-as-user"):
        _config(["--dc", "dc1", "--target-domain", "corp.local", "--target-user", "alice"])


def test_run_policy_skips_target_methods_without_target_user(monkeypatch):
    # The per-user methods that need --target-user, and the oracles that need a bind, are skipped (not run)
    # when their precondition is missing; the skip reason is recorded for the reachability map.
    monkeypatch.setattr(pwpolicy, "_run_samr", lambda *a, **k: None)
    monkeypatch.setattr(pwpolicy, "_run_ldap", lambda *a, **k: None)
    monkeypatch.setattr(pwpolicy, "_run_kpasswd", lambda *a, **k: None)
    monkeypatch.setattr(pwpolicy, "_run_sysvol", lambda *a, **k: None)
    cfg = _config(["--dc", "dc1", "--target-domain", "corp.local", "--anonymous"])
    result = pwpolicy._run_policy(cfg)
    assert result.reachability["samr-getusrpwinfo"] == "skipped: no --target-user"
    assert result.reachability["ldap-resultant"] == "skipped: no --target-user"
    assert result.reachability["samr-diag"] == "skipped: needs authentication"
    assert result.reachability["kpasswd"] == "skipped: needs authentication"
    assert result.user_view is None


def test_attempt_records_wire_failure_without_crashing():
    # An LDAP bind/session failure (e.g. bad credentials) must be recorded as a reachability verdict,
    # not raised out of the tool: LDAPSearchError subclasses LDAPSessionError, so _attempt catches both.
    result = PolicyReadResult(target="t", dc="dc")

    def boom():
        raise LDAPSessionError(errorString="invalidCredentials")

    assert pwpolicy._attempt(result, "ldap-domain-head", boom) is None
    assert "invalidCredentials" in result.reachability["ldap-domain-head"]
