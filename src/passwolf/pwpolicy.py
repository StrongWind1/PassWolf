"""passwolf policy: read the Active Directory password policy over every channel a DC exposes it on.

Reading the policy is a third operation, distinct from changing and resetting a password, so it lives in
its own tool with no path that can mutate a secret. passwolf policy gathers the domain-wide default policy and,
when --target-user is given, that account's PSO-effective policy, over the SAMR domain-query classes and the
handle-light / per-user getters, the opnum-63 change-failure oracle, the Kerberos kpasswd SOFTERROR blob,
the LDAP domain head and fine-grained PSO objects, and the SYSVOL configured intent. Authentication comes
solely from the --auth-as-* flags; the oracles report the effective policy of that authenticated principal. Every
method runs independently and its reachability is recorded, so an anonymous run shows exactly which channels
leak the policy and which deny it, rather than collapsing to one answer.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.ldap.ldap import LDAPSessionError
from impacket.smbconnection import SessionError

from . import __version__, policy
from .console import render_policy
from .errors import MethodUnavailable, OperationFailed
from .model import OutputFormat, Secret, Target, TransportKind, parse_hash_pair, prompt_password
from .policymodel import PasswordPolicy, PolicyReadResult, UserPolicyView
from .transport import BindIdentity, open_channel

if TYPE_CHECKING:
    from collections.abc import Callable

    from .policymodel import PsoPolicy

LOG = logging.getLogger("pwpolicy")

_T = TypeVar("_T")

# --- Method identifiers (kept local so the change/reset model is not polluted with a read vocabulary) ---
SAMR_QUERY = "samr-query"
SAMR_GETDOM = "samr-getdompwinfo"
SAMR_GETUSR = "samr-getusrpwinfo"
SAMR_DIAG = "samr-diag"
KPASSWD = "kpasswd"
LDAP_DOMAIN = "ldap-domain-head"
LDAP_PSO = "ldap-pso"
LDAP_RESULTANT = "ldap-resultant"
LDAP_UAC = "ldap-uac"
SYSVOL = "sysvol"
ALL = "all"

_SAMR_METHODS = (SAMR_QUERY, SAMR_GETDOM, SAMR_GETUSR, SAMR_DIAG)
_LDAP_METHODS = (LDAP_DOMAIN, LDAP_PSO, LDAP_RESULTANT, LDAP_UAC)
# Methods that resolve a named account's fine-grained policy without that account's secret; they need
# --target-user and are skipped without it.
_TARGET_METHODS = (SAMR_GETUSR, LDAP_RESULTANT, LDAP_UAC)
# Change-failure oracles: they prove identity as the authenticating principal and report its effective
# policy, so they require a non-anonymous bind (no separate subject secret is taken).
_ORACLE_METHODS = (SAMR_DIAG, KPASSWD)
_ALL_METHODS = (SAMR_QUERY, SAMR_GETDOM, SAMR_GETUSR, SAMR_DIAG, KPASSWD, LDAP_DOMAIN, LDAP_PSO, LDAP_RESULTANT, LDAP_UAC, SYSVOL)
_METHOD_CHOICES = (ALL, *_ALL_METHODS)


@dataclass(frozen=True)
class PolicyConfig:
    """A fully resolved policy-read request.

    Authentication is carried entirely by ``bind`` (from the --auth-as-* flags); there is no separate subject
    credential. ``target_user`` is the optional ``--target-user`` whose fine-grained (PSO) effective policy
    the per-user methods resolve, and it needs no secret of its own. The opnum-63 and kpasswd oracles prove
    identity as ``bind`` and so report the authenticating principal's effective policy.
    """

    target: Target  # domain controller plus the --target-user account (user field, may be empty)
    bind: BindIdentity  # the principal that authenticates every read (empty for anonymous)
    target_user: str  # --target-user: the account whose PSO-effective policy is resolved (may be empty)
    anonymous: bool
    methods: tuple[str, ...]
    transport: TransportKind
    use_ldaps: bool
    output: OutputFormat

    @property
    def label(self) -> str:
        r"""Return a printable label for the read (DOMAIN\target-user, or the domain when no target)."""
        if self.target_user:
            return f"{self.target.domain}\\{self.target_user}"
        return self.target.domain or self.target.dc


@dataclass
class _UserParts:
    """Per-target-user fragments collected during the run and assembled into a UserPolicyView at the end.

    These all describe ``--target-user``. The op63/kpasswd oracle records are not held here because they
    report the authenticating principal's effective policy; they are appended straight to result.policies.
    """

    op44: PasswordPolicy | None = None
    resultant_dn: str | None = None
    effective_pso: PsoPolicy | None = None
    locked: bool | None = None
    expired: bool | None = None
    bad_pwd: int | None = None
    resultant_seen: bool = False
    uac_seen: bool = False


def _classify(exc: Exception) -> str:
    """Map a wire exception to a short reachability verdict, distinguishing denial from absence."""
    text = str(exc)
    lowered = text.lower()
    if "access_denied" in lowered or "access denied" in lowered or "0x00000005" in text or "insufficientaccessrights" in lowered:
        return "denied"
    return f"unavailable: {text}"


def _attempt(result: PolicyReadResult, method_id: str, run: Callable[[], _T]) -> _T | None:
    """Run one method, record its reachability verdict, and return its value (None on any failure)."""
    try:
        value = run()
    except MethodUnavailable as exc:
        result.reachability[method_id] = _classify(exc)
        return None
    except OperationFailed as exc:
        result.reachability[method_id] = f"failed: {exc}"
        return None
    except (DCERPCException, LDAPSessionError, SessionError, OSError) as exc:
        result.reachability[method_id] = _classify(exc)
        return None
    result.reachability[method_id] = "ok"
    return value


# --- SAMR group: one channel serves all four SAMR reads ---
def _samr_getdom(dce: object, result: PolicyReadResult) -> None:
    """Run the handle-light opnum-56 read and record its policy."""
    got = _attempt(result, SAMR_GETDOM, lambda: policy.samr_get_domain_password_information(dce))
    if isinstance(got, PasswordPolicy):
        result.policies.append(got)


def _samr_query(dce: object, domain_handle: object, result: PolicyReadResult) -> None:
    """Run the opnum-46 domain-query read and record its policy."""
    got = _attempt(result, SAMR_QUERY, lambda: policy.samr_password_policy(dce, domain_handle))
    if isinstance(got, PasswordPolicy):
        result.policies.append(got)


def _samr_getusr(dce: object, domain_handle: object, cfg: PolicyConfig, result: PolicyReadResult, parts: _UserParts) -> None:
    """Run the per-user opnum-44 read for --target-user and record its PSO-effective policy."""
    got = _attempt(result, SAMR_GETUSR, lambda: policy.samr_get_user_password_information(dce, domain_handle, cfg.target_user))
    if isinstance(got, PasswordPolicy):
        result.policies.append(got)
        parts.op44 = got


def _samr_diag(dce: object, cfg: PolicyConfig, result: PolicyReadResult) -> None:
    """Run the opnum-63 oracle as the authenticated principal and record its effective policy."""
    got = _attempt(result, SAMR_DIAG, lambda: policy.samr_oracle_policy(dce, cfg.bind.user, _bind_secret(cfg)))
    if isinstance(got, tuple):
        record, _reason = got  # the extended failure reason is diagnostic only and not rendered
        result.policies.append(record)


def _run_samr_handle_group(dce: object, cfg: PolicyConfig, result: PolicyReadResult, parts: _UserParts, selected: set[str]) -> None:
    """Open the domain handle once (when needed) and run the handle-dependent SAMR reads."""
    needs_handle = {SAMR_QUERY, SAMR_GETUSR} & selected
    if needs_handle:
        try:
            domain_handle, _, _ = policy.open_domain_handle(dce)
        except DCERPCException as exc:
            for method_id in needs_handle:
                result.reachability[method_id] = _classify(exc)
        else:
            if SAMR_QUERY in selected:
                _samr_query(dce, domain_handle, result)
            if SAMR_GETUSR in selected:
                _samr_getusr(dce, domain_handle, cfg, result, parts)
    if SAMR_DIAG in selected:
        _samr_diag(dce, cfg, result)


def _run_samr(cfg: PolicyConfig, result: PolicyReadResult, parts: _UserParts, selected: set[str]) -> None:
    """Open one SAMR channel and run every selected SAMR read against it."""
    wanted = [m for m in _SAMR_METHODS if m in selected]
    if not wanted:
        return
    try:
        channel = open_channel(cfg.target, cfg.bind, policy.SAMR_UUID, policy.SAMR_PIPE, cfg.transport)
    except (DCERPCException, SessionError, OSError) as exc:
        for method_id in wanted:
            result.reachability[method_id] = _classify(exc)
        return
    try:
        if SAMR_GETDOM in selected:
            _samr_getdom(channel.dce, result)
        _run_samr_handle_group(channel.dce, cfg, result, parts, selected)
    finally:
        channel.close()


# --- kpasswd group ---
def _run_kpasswd(cfg: PolicyConfig, result: PolicyReadResult) -> None:
    """Probe the kpasswd SOFTERROR policy as the authenticated principal (works on Server 2025)."""
    auth_user = cfg.bind.user
    got = _attempt(result, KPASSWD, lambda: policy.kpasswd_softerror_policy(cfg.target, auth_user, cfg.target.domain, _bind_secret(cfg)))
    if isinstance(got, PasswordPolicy):
        result.policies.append(got)


# --- LDAP group ---
def _run_ldap(cfg: PolicyConfig, result: PolicyReadResult, parts: _UserParts, selected: set[str]) -> None:
    """Run the selected LDAP reads, each over its own bind (matching the change/reset LDAP path)."""
    if LDAP_DOMAIN in selected:
        got = _attempt(result, LDAP_DOMAIN, lambda: policy.ldap_domain_head(cfg.target, cfg.bind, use_ldaps=cfg.use_ldaps))
        if isinstance(got, PasswordPolicy):
            result.policies.append(got)
    if LDAP_PSO in selected:
        got = _attempt(result, LDAP_PSO, lambda: policy.ldap_password_settings_objects(cfg.target, cfg.bind, use_ldaps=cfg.use_ldaps))
        if isinstance(got, list):
            result.psos.extend(got)
    if LDAP_RESULTANT in selected:
        got = _attempt(result, LDAP_RESULTANT, lambda: policy.ldap_resultant_pso(cfg.target, cfg.bind, cfg.target_user, use_ldaps=cfg.use_ldaps))
        if isinstance(got, tuple):
            parts.resultant_seen = True
            parts.resultant_dn, parts.effective_pso = got
    if LDAP_UAC in selected:
        got = _attempt(result, LDAP_UAC, lambda: policy.ldap_user_account_computed(cfg.target, cfg.bind, cfg.target_user, use_ldaps=cfg.use_ldaps))
        if isinstance(got, tuple):
            parts.uac_seen = True
            parts.locked, parts.expired, parts.bad_pwd = got


# --- SYSVOL group ---
def _run_sysvol(cfg: PolicyConfig, result: PolicyReadResult) -> None:
    """Read the SYSVOL GPO security templates (configured intent)."""
    got = _attempt(result, SYSVOL, lambda: policy.sysvol_gpttmpl_policies(cfg.target, cfg.bind))
    if isinstance(got, list):
        result.gpo_policies.extend(got)


def _bind_secret(cfg: PolicyConfig) -> Secret:
    """Return the bind principal's own secret, used by kpasswd for the self-change probe."""
    return Secret(password=cfg.bind.password or None, nt_hash=cfg.bind.nt_hash)


def _assemble_user_view(cfg: PolicyConfig, parts: _UserParts) -> UserPolicyView | None:
    """Fold the --target-user fragments into a UserPolicyView, or None when no target user was given."""
    if not cfg.target_user:
        return None
    return UserPolicyView(
        principal=f"{cfg.target.domain}\\{cfg.target_user}",
        resultant_pso=parts.resultant_dn,
        effective_pso=parts.effective_pso,
        op44_min_length=parts.op44.min_password_length if parts.op44 else None,
        op44_complexity=parts.op44.complexity_enabled if parts.op44 else None,
        op44_reversible=parts.op44.reversible_encryption if parts.op44 else None,
        is_locked_out=parts.locked,
        password_expired=parts.expired,
        bad_password_count=parts.bad_pwd,
    )


def _skip(result: PolicyReadResult, selected: set[str], methods: tuple[str, ...], reason: str) -> None:
    """Mark each still-selected method in ``methods`` as skipped (not failed) and drop it from the run."""
    for method_id in methods:
        if method_id in selected:
            result.reachability[method_id] = f"skipped: {reason}"
            selected.discard(method_id)


def _run_policy(cfg: PolicyConfig) -> PolicyReadResult:
    """Run every selected method, recording each one's reachability, and assemble the result."""
    result = PolicyReadResult(target=cfg.label, dc=cfg.target.dc)
    selected = set(cfg.methods)
    parts = _UserParts()

    # Resolving a named account's fine-grained policy needs --target-user; the oracles prove identity as
    # the authenticated principal, so they need a non-anonymous bind. Both gaps are skips, not failures.
    if not cfg.target_user:
        _skip(result, selected, _TARGET_METHODS, "no --target-user")
    if cfg.anonymous:
        _skip(result, selected, _ORACLE_METHODS, "needs authentication")

    _run_samr(cfg, result, parts, selected)
    if KPASSWD in selected:
        _run_kpasswd(cfg, result)
    _run_ldap(cfg, result, parts, selected)
    if SYSVOL in selected:
        _run_sysvol(cfg, result)

    result.user_view = _assemble_user_view(cfg, parts)
    return result


def _build_config(args: argparse.Namespace) -> PolicyConfig:
    """Resolve parsed arguments into a PolicyConfig, with auth taken solely from the --auth-as-* flags."""
    # --target-domain is required; the DC and the auth-as domain both default to it when omitted.
    domain = args.target_domain
    auth_domain = args.auth_as_domain or domain
    dc = args.dc or domain

    if args.anonymous:
        bind = BindIdentity(user="", domain=auth_domain, password="")
    else:
        if not args.auth_as_user:
            msg = "sign in with --auth-as-user, or pass --anonymous"
            raise ValueError(msg)
        _, bind_nt = parse_hash_pair(args.auth_as_hash)
        auth_password = args.auth_as_password
        # With Kerberos the bind can come from the ticket cache, so only prompt for a password under NTLM.
        if auth_password is None and bind_nt is None and not args.kerberos:
            auth_password = prompt_password(f"Password for {args.auth_as_user}")
        bind = BindIdentity(user=args.auth_as_user, domain=auth_domain, password=auth_password or "", nt_hash=bind_nt, use_kerberos=args.kerberos)

    # --target-user defaults to the authenticated principal, so an authenticated run reads its own
    # PSO-effective policy with no extra flag; an anonymous bind has no principal, leaving it empty (which
    # skips the per-user methods). An explicit --target-user always wins.
    target_user = args.target_user or bind.user

    methods: tuple[str, ...] = _ALL_METHODS if args.method == ALL else (args.method,)
    target = Target(domain=domain, user=target_user, dc=dc)
    return PolicyConfig(
        target=target,
        bind=bind,
        target_user=target_user,
        anonymous=args.anonymous,
        methods=methods,
        transport=TransportKind(args.transport),
        use_ldaps=args.ldaps,
        output=OutputFormat(args.format),
    )


_DESCRIPTION = """\
Read the Active Directory password policy over every channel a domain controller exposes it on.

Reading the policy is a third operation, distinct from changing and resetting a password, and it mutates
nothing. passwolf policy reports the domain-wide default policy over the SAMR domain-query classes, the LDAP domain
head, and the SYSVOL security templates, and also resolves a named account's fine-grained (PSO) effective
policy over the per-user SAMR getter and the LDAP resultant-PSO and computed account-control reads. That
account defaults to the principal you authenticate as (override it with --target-user), so an authenticated
run reads its own effective policy by default. The opnum-63 and Kerberos kpasswd change-failure oracles
report the policy effective for the authenticated principal. Each method runs independently and its reachability is
reported, so an anonymous run shows exactly which channels leak the policy and which deny it. Every row is
labelled domain or PSO so it is clear whether a value is the domain default or a fine-grained policy."""

_EPILOG = """\
examples:
  # read the domain default and your own effective policy as a low-privileged user
  passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe --auth-as-password 'Passw0rd!'

  # probe anonymously to see which channels leak the policy on this DC
  passwolf policy --dc dc01.corp.local --target-domain corp.local --anonymous

  # resolve another account's fine-grained (PSO) effective policy
  passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-user jdoe

  # enumerate the fine-grained password policies and emit JSON
  passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --method ldap-pso --format json

note: the opnum-63 and kpasswd oracles report the policy effective for the principal you authenticate as;
to read a specific user's PSO-effective policy through them, authenticate as that user.

exit status: 0 when at least one method returned policy data, 1 when every method was denied or
unavailable, 2 on a usage error.

note: credentials passed on the command line may be visible to other local users via the process list.

documentation: https://strongwind1.github.io/passwolf/"""


def _build_parser() -> argparse.ArgumentParser:
    """Build the passwolf policy command line."""
    parser = argparse.ArgumentParser(
        prog="passwolf policy",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    server = parser.add_argument_group("the domain to read")
    server.add_argument("--target-domain", required=True, metavar="NAME", help="(required) the Active Directory domain to read the policy from, such as corp.local (also used for the LDAP, Kerberos, and SYSVOL reads)")
    server.add_argument("--dc", metavar="HOST", help="(optional) the domain controller to connect to, by hostname or IP address; defaults to the --target-domain name")

    auth = parser.add_argument_group("how to sign in (required: give --auth-as-user or --anonymous)")
    auth.add_argument("--auth-as-user", metavar="NAME", help="the account to sign in as")
    auth.add_argument("--auth-as-password", metavar="PASS", help="(optional) that account's password; prompted for if you give --auth-as-user with neither this nor --auth-as-hash")
    auth.add_argument("--auth-as-hash", metavar="[LM:]NT", help="(optional) that account's NT hash, to sign in without its plain-text password")
    auth.add_argument("--auth-as-domain", metavar="NAME", help="(optional) that account's domain; defaults to the --target-domain name")
    auth.add_argument("-k", "--kerberos", action="store_true", help="(optional) authenticate with Kerberos instead of NTLM; uses the ticket cache named by KRB5CCNAME, or fetches a ticket with the password or hash")
    auth.add_argument("--anonymous", action="store_true", help="connect with no credentials at all, to see what an unauthenticated user can read")

    scope = parser.add_argument_group("whose fine-grained policy to resolve")
    scope.add_argument("--target-user", metavar="NAME", help="report this account's fine-grained (PSO) effective policy; defaults to the account you sign in as, so a signed-in run reports its own")

    selection = parser.add_argument_group("which reads to run")
    selection.add_argument("--method", choices=_METHOD_CHOICES, default=ALL, metavar="METHOD", help="which read to run; leave as 'all' (the default) to try every channel. one of: " + ", ".join(_METHOD_CHOICES))
    selection.add_argument("--transport", choices=[t.value for t in TransportKind], default=TransportKind.SMB.value, help="how to reach the server for the SAMR reads: over an SMB named pipe or a direct TCP connection (default smb)")
    selection.add_argument("--ldaps", action="store_true", help="for the LDAP reads, connect with encryption on port 636 instead of port 389")

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=[f.value for f in OutputFormat], default=OutputFormat.PRETTY.value, help="how to print the result: plain text, JSON, or a formatted box (default pretty)")
    output.add_argument("-v", "--verbose", action="store_true", help="print detailed logging for troubleshooting")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the passwolf policy console script."""
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = _build_config(args)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2

    result = _run_policy(cfg)
    print(render_policy(result, cfg.output))
    # Exit 0 when at least one method returned policy data, 1 when every method was denied or unavailable.
    return 0 if any(status == "ok" for status in result.reachability.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
