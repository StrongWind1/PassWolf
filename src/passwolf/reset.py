"""passwolf reset: reset an Active Directory password by privileged overwrite.

A reset proves nothing about the old password and requires a privileged caller. passwolf reset speaks every
reset method: the SAMR AES cleartext reset (SamrSetInformationUser2 + UserInternal7), the legacy RC4
cleartext reset, the set-hash reset (UserInternal1), the DSRM reset (opnum 66, selected with --dsrm),
the Kerberos set protocol, and the LDAP unicodePwd replace. AUTO walks every method in turn -- Kerberos,
LDAPS, sealed LDAP, then the SAMR ladder (AES, RC4, RC4-unsalted, set-hash) -- and takes the first that
succeeds.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.krb5.kerberosv5 import KerberosError
from impacket.ldap.ldap import LDAPSessionError
from impacket.smbconnection import SessionError

from . import __version__, crypto, kpasswd, ldap, samr
from .console import Outcome, render
from .constants import (
    OPNUM_SAMR_SET_INFORMATION_USER,
    OPNUM_SAMR_SET_INFORMATION_USER2,
    USER_ALL_INFORMATION,
    USER_INTERNAL1_INFORMATION,
    USER_INTERNAL4_INFORMATION,
    USER_INTERNAL4_INFORMATION_NEW,
    USER_INTERNAL5_INFORMATION,
    USER_INTERNAL5_INFORMATION_NEW,
    USER_INTERNAL7_INFORMATION,
    USER_INTERNAL8_INFORMATION,
)
from .errors import MethodUnavailable, OperationFailed
from .model import (
    OutputFormat,
    ResetMethod,
    Secret,
    Target,
    TransportKind,
    parse_hash_pair,
    prompt_password,
)
from .nterror import STATUS_SUCCESS, STATUS_UNSUCCESSFUL
from .transport import BindIdentity, open_channel

if TYPE_CHECKING:
    from collections.abc import Callable

    from .transport import Channel

LOG = logging.getLogger("pwreset")

# Friendly names for the advanced --reset-info-class control, mapped to their USER_INFORMATION_CLASS
# value. These are the eight settable password-bearing classes, in natural numeric order.
_INFO_CLASS_BY_NAME: dict[str, int] = {
    "internal1": USER_INTERNAL1_INFORMATION,
    "userall": USER_ALL_INFORMATION,
    "internal4": USER_INTERNAL4_INFORMATION,
    "internal5": USER_INTERNAL5_INFORMATION,
    "internal4new": USER_INTERNAL4_INFORMATION_NEW,
    "internal5new": USER_INTERNAL5_INFORMATION_NEW,
    "internal7": USER_INTERNAL7_INFORMATION,
    "internal8": USER_INTERNAL8_INFORMATION,
}
_INFO_CLASS_NAME_BY_VALUE: dict[int, str] = {value: name for name, value in _INFO_CLASS_BY_NAME.items()}
_RESET_OPNUMS: dict[str, int] = {"37": OPNUM_SAMR_SET_INFORMATION_USER, "58": OPNUM_SAMR_SET_INFORMATION_USER2}

# Label AUTO prints for the LDAPS attempt; the other steps reuse their ResetMethod value as the label.
_LDAPS_LABEL = "ldaps"
# Errors that mean "this AUTO step did not apply"; AUTO records them and falls through to the next method.
_AUTO_FALLBACK_ERRORS = (MethodUnavailable, OperationFailed, DCERPCException, SessionError, KerberosError, LDAPSessionError, OSError)


@dataclass(frozen=True)
class ResetConfig:
    """A fully resolved reset request."""

    target: Target
    new_password: str | None
    new_nt_hash: bytes | None
    new_lm_hash: bytes | None
    method: ResetMethod
    transport: TransportKind
    bind: BindIdentity
    expire: bool
    use_ldaps: bool
    output: OutputFormat
    # Advanced SAMR selection: when reset_info_class is set it overrides --method and sends that exact
    # USER_INFORMATION_CLASS over reset_opnum (37 or 58). Both are None for the standard method paths.
    reset_opnum: int | None = None
    reset_info_class: int | None = None

    @property
    def label(self) -> str:
        r"""Return a printable DOMAIN\user label for the target account."""
        return f"{self.target.domain}\\{self.target.user}"

    def require_password(self) -> str:
        """Return the cleartext new password or raise when only a hash was supplied."""
        if self.new_password is None:
            msg = "this reset method needs a cleartext new password (--new)"
            raise MethodUnavailable(msg)
        return self.new_password

    def require_nt_hash(self) -> bytes:
        """Return the new NT hash to set, deriving it from the cleartext password when no hash was given.

        The set-hash reset accepts an explicit NT hash (``--target-new-hash``) for a true policy-bypass
        set, or a cleartext password (``--target-new-password``), which is hashed locally into its NT OWF.
        """
        if self.new_nt_hash is not None:
            return self.new_nt_hash
        if self.new_password is not None:
            return crypto.nt_owf(self.new_password)
        msg = "the set-hash reset needs a new NT hash (--target-new-hash) or a cleartext password"
        raise MethodUnavailable(msg)


def _run_samr_reset(cfg: ResetConfig) -> tuple[str, int]:
    """Open a SAMR channel as the privileged caller and run the requested (or AUTO-selected) reset.

    Returns the printable method label, so the advanced opnum/info-class path can name the exact wire
    form it sent rather than squeezing it into a ResetMethod value.
    """
    channel = open_channel(cfg.target, cfg.bind, samr.SAMR_UUID, samr.SAMR_PIPE, cfg.transport)
    try:
        user_handle, _ = samr.open_user_handle(channel.dce, cfg.target.user)
        if cfg.reset_info_class is not None:
            return _run_advanced_samr_reset(channel, cfg, user_handle, cfg.reset_info_class)
        return _run_standard_samr_reset(channel, cfg, user_handle)
    finally:
        channel.close()


def _run_standard_samr_reset(channel: Channel, cfg: ResetConfig, user_handle: object) -> tuple[str, int]:
    """Run a named SAMR reset method (--method); AUTO walks the SAMR ladder over the open channel."""
    if cfg.method is ResetMethod.SAMR_HASH:
        return ResetMethod.SAMR_HASH.value, samr.reset_hash(channel.dce, user_handle, channel.session_key, cfg.require_nt_hash(), cfg.new_lm_hash, expire=cfg.expire)
    if cfg.method is ResetMethod.SAMR_RC4:
        return ResetMethod.SAMR_RC4.value, samr.reset_rc4(channel.dce, user_handle, channel.session_key, cfg.require_password(), expire=cfg.expire)
    if cfg.method is ResetMethod.SAMR_RC4_UNSALTED:
        return ResetMethod.SAMR_RC4_UNSALTED.value, samr.reset_rc4_unsalted(channel.dce, user_handle, channel.session_key, cfg.require_password(), expire=cfg.expire)
    if cfg.method is ResetMethod.SAMR_AES:
        return ResetMethod.SAMR_AES.value, samr.reset_aes(channel.dce, user_handle, channel.session_key, cfg.require_password(), expire=cfg.expire)
    return _auto_samr_ladder(channel, cfg, user_handle, [])


def _run_advanced_samr_reset(channel: Channel, cfg: ResetConfig, user_handle: object, info_class: int) -> tuple[str, int]:
    """Advanced path: send the chosen USER_INFORMATION_CLASS over the chosen opnum (37 or 58)."""
    opnum = cfg.reset_opnum or OPNUM_SAMR_SET_INFORMATION_USER2
    status = samr.reset_set_information(
        channel.dce,
        user_handle,
        channel.session_key,
        opnum=opnum,
        info_class=info_class,
        new_password=cfg.new_password,
        nt_hash=cfg.new_nt_hash,
        lm_hash=cfg.new_lm_hash,
        expire=cfg.expire,
    )
    return f"samr-{_INFO_CLASS_NAME_BY_VALUE[info_class]}-op{opnum}", status


def _try_auto_method(label: str, attempt: Callable[[], int], failures: list[str]) -> tuple[str, int] | None:
    """Run one AUTO step: return ``(label, status)`` on a clean success, else record why and return None.

    A step is taken only when it raises no availability error and reports STATUS_SUCCESS; anything else
    (an unavailable method, a closed port, a non-success status) is logged and AUTO moves to the next.
    """
    try:
        status = attempt()
    except _AUTO_FALLBACK_ERRORS as exc:
        LOG.info("auto: %s did not apply (%s); trying the next method", label, exc)
        failures.append(f"{label}: {exc}")
        return None
    if status == STATUS_SUCCESS:
        return label, status
    LOG.info("auto: %s returned status 0x%08x; trying the next method", label, status)
    failures.append(f"{label}: status 0x{status:08x}")
    return None


def _auto_samr_ladder(channel: Channel, cfg: ResetConfig, user_handle: object, failures: list[str]) -> tuple[str, int]:
    """Walk the SAMR tail of AUTO: AES, then RC4, then RC4-unsalted, then the set-hash reset as a last resort.

    The cleartext rungs are skipped when only a hash was supplied; the set-hash reset writes the NT OWF
    directly (derived from the cleartext when no explicit hash was given) and is the only rung that can
    apply a hash-only secret or bypass a password policy that rejected every cleartext attempt.
    """
    if cfg.new_password is not None:
        password = cfg.require_password()
        ladder: list[tuple[str, Callable[[], int]]] = []
        if samr.supports_aes(channel.dce) is not False:
            ladder.append((ResetMethod.SAMR_AES.value, lambda: samr.reset_aes(channel.dce, user_handle, channel.session_key, password, expire=cfg.expire)))
        else:
            LOG.info("auto: DC does not advertise the AES password buffer (SamrConnect5); skipping the AES reset")
        ladder.append((ResetMethod.SAMR_RC4.value, lambda: samr.reset_rc4(channel.dce, user_handle, channel.session_key, password, expire=cfg.expire)))
        ladder.append((ResetMethod.SAMR_RC4_UNSALTED.value, lambda: samr.reset_rc4_unsalted(channel.dce, user_handle, channel.session_key, password, expire=cfg.expire)))
        for label, attempt in ladder:
            taken = _try_auto_method(label, attempt, failures)
            if taken is not None:
                return taken
    taken = _try_auto_method(ResetMethod.SAMR_HASH.value, lambda: samr.reset_hash(channel.dce, user_handle, channel.session_key, cfg.require_nt_hash(), cfg.new_lm_hash, expire=cfg.expire), failures)
    if taken is not None:
        return taken
    detail = "; ".join(failures) if failures else "no reset method was available"
    msg = f"auto: every reset method failed ({detail})"
    raise MethodUnavailable(msg)


def _run_auto_reset(cfg: ResetConfig) -> tuple[str, int]:
    """AUTO: try each method in turn and return the first that succeeds.

    Order: the Kerberos set (kpasswd), the LDAP unicodePwd replace over LDAPS then sealed 389, then the
    SAMR ladder (AES, RC4, RC4-unsalted, set-hash). The non-SAMR rungs need a cleartext password, so a
    hash-only secret drops straight to the SAMR set-hash reset.
    """
    failures: list[str] = []
    if cfg.new_password is not None:
        for label, attempt in (
            (ResetMethod.KPASSWD.value, lambda: kpasswd.reset(cfg.target, cfg.bind.user, cfg.bind.domain, Secret(password=cfg.bind.password or None, nt_hash=cfg.bind.nt_hash), cfg.target.user, cfg.target.domain, cfg.require_password())),
            (_LDAPS_LABEL, lambda: ldap.reset(cfg.target, cfg.bind, cfg.target.user, cfg.require_password(), use_ldaps=True)),
            (ResetMethod.LDAP.value, lambda: ldap.reset(cfg.target, cfg.bind, cfg.target.user, cfg.require_password(), use_ldaps=False)),
        ):
            taken = _try_auto_method(label, attempt, failures)
            if taken is not None:
                return taken
    # The SAMR rungs share one named-pipe channel, opened once here.
    channel = open_channel(cfg.target, cfg.bind, samr.SAMR_UUID, samr.SAMR_PIPE, cfg.transport)
    try:
        user_handle, _ = samr.open_user_handle(channel.dce, cfg.target.user)
        return _auto_samr_ladder(channel, cfg, user_handle, failures)
    finally:
        channel.close()


def _run_dsrm_reset(cfg: ResetConfig) -> int:
    """Open a SAMR channel as the privileged caller and reset the DC-local DSRM password.

    SamrSetDSRMPassword is served only over the SMB named pipe; a direct-TCP binding is refused by the
    server with RPC_S_ACCESS_DENIED ([MS-SAMR] 3.1.5.13.6), so reject it up front for a clear error.
    """
    channel = open_channel(cfg.target, cfg.bind, samr.SAMR_UUID, samr.SAMR_PIPE, cfg.transport)
    try:
        if channel.session_key is None:
            msg = "the DSRM reset is served only over the SMB named pipe; use --transport smb"
            raise MethodUnavailable(msg)
        return samr.reset_dsrm(channel.dce, cfg.require_password())
    finally:
        channel.close()


def _run_reset(cfg: ResetConfig) -> Outcome:
    """Dispatch the reset by method and return a formatted-ready outcome."""
    extra: dict[str, str] = {}
    # The advanced --reset-info-class control overrides --method and always goes through SAMR.
    if cfg.reset_info_class is None and cfg.method is ResetMethod.DSRM:
        method_label, status = ResetMethod.DSRM.value, _run_dsrm_reset(cfg)
    elif cfg.reset_info_class is None and cfg.method is ResetMethod.AUTO:
        method_label, status = _run_auto_reset(cfg)
    elif cfg.reset_info_class is None and cfg.method is ResetMethod.KPASSWD:
        method_label = ResetMethod.KPASSWD.value
        status = kpasswd.reset(cfg.target, cfg.bind.user, cfg.bind.domain, Secret(password=cfg.bind.password or None, nt_hash=cfg.bind.nt_hash), cfg.target.user, cfg.target.domain, cfg.require_password())
    elif cfg.reset_info_class is None and cfg.method is ResetMethod.LDAP:
        method_label = ResetMethod.LDAP.value
        status = ldap.reset(cfg.target, cfg.bind, cfg.target.user, cfg.require_password(), use_ldaps=cfg.use_ldaps)
    else:
        method_label, status = _run_samr_reset(cfg)
    return Outcome(operation="reset", method=method_label, target=cfg.label, dc=cfg.target.dc, status=status, extra=extra)


def _build_config(args: argparse.Namespace) -> ResetConfig:
    """Resolve parsed arguments into a ResetConfig, including the privileged bind identity."""
    # --target-domain is required; the DC and the auth-as domain both default to it when omitted.
    domain = args.target_domain
    dc = args.dc or domain
    target = Target(domain=domain, user=args.target_user, dc=dc)

    new_lm_hash, new_nt_hash = parse_hash_pair(args.target_new_hash)
    # The new secret is a password or a raw hash; when neither was given, prompt for the password.
    new_password = args.target_new_password
    if new_password is None and new_nt_hash is None:
        new_password = prompt_password(f"New password for {target.user}")

    _, auth_nt_hash = parse_hash_pair(args.auth_as_hash)
    auth_password = args.auth_as_password
    # With Kerberos the caller can come from the ticket cache, so only prompt for a password under NTLM.
    if auth_password is None and auth_nt_hash is None and not args.kerberos:
        auth_password = prompt_password(f"Password for {args.auth_as_user}")
    auth_domain = args.auth_as_domain or domain
    bind = BindIdentity(user=args.auth_as_user, domain=auth_domain, password=auth_password or "", nt_hash=auth_nt_hash, use_kerberos=args.kerberos)

    # Advanced SAMR selection: an explicit USER_INFORMATION_CLASS (and optional opnum) overrides --method.
    reset_info_class = _INFO_CLASS_BY_NAME[args.reset_info_class] if args.reset_info_class else None
    reset_opnum = _RESET_OPNUMS[args.reset_opnum] if args.reset_opnum else None
    if reset_info_class is not None and args.dsrm:
        msg = "choose either --dsrm or --reset-info-class, not both"
        raise ValueError(msg)
    if reset_opnum is not None and reset_info_class is None:
        msg = "--reset-opnum only applies together with --reset-info-class"
        raise ValueError(msg)

    # The DC-local DSRM reset has its own selector flag; when set it overrides --method.
    method = ResetMethod.DSRM if args.dsrm else ResetMethod(args.method)
    return ResetConfig(
        target=target,
        new_password=new_password,
        new_nt_hash=new_nt_hash,
        new_lm_hash=new_lm_hash,
        method=method,
        transport=TransportKind(args.transport),
        bind=bind,
        expire=args.expire,
        use_ldaps=args.ldaps,
        output=OutputFormat(args.format),
        reset_opnum=reset_opnum,
        reset_info_class=reset_info_class,
    )


_DESCRIPTION = """\
Reset an Active Directory account password by privileged overwrite.

A reset proves nothing about the old password and requires a caller with reset rights, supplied with
--auth-as-user. passwolf reset implements every reset method over SAMR, Kerberos, and LDAP, including the AES cleartext
reset info levels that impacket lacks. The set-hash reset writes the NT (and optionally LM) one-way function
directly, bypassing complexity and length policy. AUTO tries every method in turn -- Kerberos, LDAPS, sealed
LDAP, then the SAMR ladder (AES, RC4, RC4-unsalted, set-hash) -- and takes the first that succeeds. The
DC-local DSRM recovery password is reset with the dedicated --dsrm flag."""

_EPILOG = """\
examples:
  # reset a user's password as a privileged caller
  passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'

  # set the NT hash directly (full policy bypass)
  passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash <NTHASH>

  # reset without forcing a change at next logon
  passwolf reset --target-domain corp.local --target-user svc --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!' --no-expire

  # reset the DC-local DSRM (recovery) password (--target-user is ignored)
  passwolf reset --dc dc01.corp.local --target-domain corp.local --target-user dsrm --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewDsrm1!' --dsrm

exit status: 0 on success, 1 on a failed or unavailable method, 2 on a usage error.

note: credentials passed on the command line may be visible to other local users via the process list.

documentation: https://strongwind1.github.io/passwolf/"""


def _build_parser() -> argparse.ArgumentParser:
    """Build the passwolf reset command line."""
    parser = argparse.ArgumentParser(
        prog="passwolf reset",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    target = parser.add_argument_group("the account to reset")
    target.add_argument("--target-user", required=True, metavar="NAME", help="(required) the account whose password you want to reset")
    target.add_argument("--target-domain", required=True, metavar="NAME", help="(required) the Active Directory domain the account belongs to, such as corp.local")

    secret = parser.add_argument_group("new password (give --target-new-password or --target-new-hash; prompted if you give neither)")
    secret.add_argument("--target-new-password", metavar="PASS", help="the new password to set, for the plain-text methods; prompted for if you supply neither this nor --target-new-hash")
    secret.add_argument("--target-new-hash", metavar="[LM:]NT", help="the new NT hash to set directly, written as NT or LM:NT to set both halves; this skips length and complexity rules")

    server = parser.add_argument_group("the server to connect to")
    server.add_argument("--dc", metavar="HOST", help="(optional) the domain controller to connect to, by hostname or IP address; defaults to the --target-domain name")

    auth = parser.add_argument_group("who is doing the reset (a privileged account)")
    auth.add_argument("--auth-as-user", required=True, metavar="NAME", help="(required) the privileged account performing the reset")
    auth.add_argument("--auth-as-password", metavar="PASS", help="(optional) that account's password; prompted for if you give neither this nor --auth-as-hash")
    auth.add_argument("--auth-as-hash", metavar="[LM:]NT", help="(optional) that account's NT hash, to sign in without its plain-text password")
    auth.add_argument("--auth-as-domain", metavar="NAME", help="(optional) that account's domain; defaults to the --target-domain name")
    auth.add_argument("-k", "--kerberos", action="store_true", help="(optional) authenticate the caller with Kerberos instead of NTLM; uses the ticket cache named by KRB5CCNAME, or fetches a ticket with the password or hash")

    # UserInternal8 (the all-information AES reset) is reached through --reset-info-class internal8, not a
    # --method shortcut; DSRM has its own --dsrm flag. Both are therefore excluded from the --method list.
    method_choices = [m.value for m in ResetMethod if m is not ResetMethod.DSRM]
    selection = parser.add_argument_group("how to do the reset")
    method_help = "which technique to use; leave as 'auto' (the default) to try each in turn (kpasswd, ldaps, ldap, samr-aes, samr-rc4, samr-rc4-unsalted, samr-hash) and take the first that works. one of: " + ", ".join(method_choices)
    selection.add_argument("--method", choices=method_choices, default=ResetMethod.AUTO.value, metavar="METHOD", help=method_help)
    selection.add_argument("--transport", choices=[t.value for t in TransportKind], default=TransportKind.SMB.value, help="how to reach the server for the SAMR methods: over an SMB named pipe or a direct TCP connection (default smb)")
    selection.add_argument("--ldaps", action="store_true", help="for the LDAP method, connect with encryption on port 636 instead of port 389")

    info_class_names = list(_INFO_CLASS_BY_NAME)
    info_class_help = "(advanced) send the reset using this exact USER_INFORMATION_CLASS, overriding --method. the hash classes (internal1, userall) take a new hash or a cleartext password (hashed locally); the rest need a cleartext password. one of: " + ", ".join(info_class_names)
    advanced = parser.add_argument_group("advanced SAMR selection (override --method; pick the exact wire form)")
    advanced.add_argument("--reset-info-class", choices=info_class_names, metavar="CLASS", help=info_class_help)
    advanced.add_argument("--reset-opnum", choices=list(_RESET_OPNUMS), metavar="{37,58}", help="(advanced) which SAMR opnum carries the reset: 37 (SamrSetInformationUser) or 58 (SamrSetInformationUser2, the default). only meaningful with --reset-info-class; older servers may reject the newer info classes on 37")

    expiry = parser.add_argument_group("must the user change it at next sign-in").add_mutually_exclusive_group()
    expiry.add_argument("--expire", dest="expire", action="store_true", help="require the user to set a new password at next sign-in (default)")
    expiry.add_argument("--no-expire", dest="expire", action="store_false", help="let the user keep this password without being prompted to change it")
    parser.set_defaults(expire=True)

    dsrm = parser.add_argument_group("recovery (DSRM) password")
    dsrm.add_argument("--dsrm", action="store_true", help="reset the domain controller's local Directory Services Restore Mode recovery password instead; works over SMB only, and --target-user is ignored")

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=[f.value for f in OutputFormat], default=OutputFormat.PRETTY.value, help="how to print the result: plain text, JSON, or a formatted box (default pretty)")
    output.add_argument("-v", "--verbose", action="store_true", help="print detailed logging for troubleshooting")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the passwolf reset console script."""
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = _build_config(args)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2

    try:
        outcome = _run_reset(cfg)
    except MethodUnavailable as exc:
        LOG.error("method unavailable: %s", exc)
        return 1
    except OperationFailed as exc:
        outcome = Outcome(operation="reset", method=cfg.method.value, target=cfg.label, dc=cfg.target.dc, status=STATUS_UNSUCCESSFUL, extra={"detail": str(exc)})
    except DCERPCException as exc:
        LOG.error("RPC error: %s", exc)
        return 1
    except SessionError as exc:
        LOG.error("authentication failed: %s", exc)
        return 1

    print(render(outcome, cfg.output))
    return 0 if outcome.success else 1


if __name__ == "__main__":
    sys.exit(main())
