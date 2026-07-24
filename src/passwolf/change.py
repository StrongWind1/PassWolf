# SPDX-License-Identifier: Apache-2.0
"""passwolf change: change an Active Directory password by proving the account's current secret.

A change needs no privilege on the target; it proves the old password (or its NT hash). passwolf change speaks
every change method: the SAMR AES change (opnum 73, the only one Server 2025 accepts), the legacy SAMR
RC4/OEM/DES changes (55, 54, 38), the undocumented diagnostic change (63), the Kerberos change protocol,
the LDAP unicodePwd change, and the Netlogon machine/trust change (opnums 30 and 6). AUTO prefers the
strongest method the DC accepts and falls back only when a method is genuinely unavailable.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import USER_CHANGE_PASSWORD
from impacket.smbconnection import SessionError

from . import __version__, kpasswd, ldap, netlogon, rap, samr
from .console import Outcome, render
from .constants import PBKDF2_ITERATIONS_DEFAULT
from .errors import MethodUnavailable, OperationFailed
from .model import (
    AccountKind,
    ChangeMethod,
    OutputFormat,
    Secret,
    Target,
    TransportKind,
    parse_hash_pair,
    prompt_password,
)
from .nterror import STATUS_NOT_SUPPORTED, STATUS_PASSWORD_EXPIRED, STATUS_PASSWORD_MUST_CHANGE, STATUS_UNSUCCESSFUL, name
from .transport import BindIdentity, open_channel

if TYPE_CHECKING:
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5

    from .transport import Channel

LOG = logging.getLogger("pwchange")


@dataclass(frozen=True)
class ChangeConfig:
    """A fully resolved change request."""

    target: Target
    new_password: str | None
    old: Secret
    account: AccountKind
    method: ChangeMethod
    transport: TransportKind
    bind: BindIdentity
    netbios: str
    use_ldaps: bool
    output: OutputFormat
    new_nt_hash: bytes | None = None
    new_lm_hash: bytes | None = None

    @property
    def label(self) -> str:
        r"""Return a printable DOMAIN\user label for the target account."""
        return f"{self.target.domain}\\{self.target.user}"

    def require_new_password(self) -> str:
        """Return the cleartext new password, or raise when only a new hash was supplied.

        Every method except the DES change (opnum 38) sets the new password from cleartext; the set-by-hash
        path is DES-only, so the other methods demand a real password here.
        """
        if self.new_password is None:
            msg = "this change method needs a cleartext new password (--target-new-password); only --method samr-des can set a raw hash"
            raise MethodUnavailable(msg)
        return self.new_password


def _samr_change_once(dce: DCERPC_v5, cfg: ChangeConfig, method: ChangeMethod) -> tuple[int, dict[str, str]]:
    """Run one SAMR change method against an already-bound channel."""
    user = cfg.target.user
    if method is ChangeMethod.SAMR_AES:
        return samr.change_aes(dce, "\x00", user, cfg.require_new_password(), cfg.old, PBKDF2_ITERATIONS_DEFAULT), {}
    if method is ChangeMethod.SAMR_RC4:
        return samr.change_rc4(dce, user, cfg.require_new_password(), cfg.old), {}
    if method is ChangeMethod.SAMR_OEM:
        return samr.change_oem(dce, user, cfg.require_new_password(), cfg.old), {}
    if method is ChangeMethod.SAMR_DES:
        user_handle, _ = samr.open_user_handle(dce, user, USER_CHANGE_PASSWORD)
        return samr.change_des(dce, user_handle, cfg.old, new_password=cfg.new_password, new_nt_hash=cfg.new_nt_hash, new_lm_hash=cfg.new_lm_hash), {}
    return samr.change_diag(dce, "\x00", user, cfg.require_new_password(), cfg.old)


# The buffer-based changes carry the old-secret proof in the request itself, so the server accepts them
# over a null session and they can change an expired ("must change at next logon") password. The DES change
# (and AUTO, which only ever resolves to a buffer change) need a user handle, which a null session is denied.
_BUFFER_CHANGE_METHODS = frozenset({ChangeMethod.AUTO, ChangeMethod.SAMR_AES, ChangeMethod.SAMR_RC4, ChangeMethod.SAMR_OEM, ChangeMethod.SAMR_DIAG})


def _bind_status(exc: Exception) -> int | None:
    """Return the NTSTATUS behind a failed bind, from the impacket error code or its rendered name."""
    code = getattr(exc, "getErrorCode", getattr(exc, "get_error_code", None))
    if callable(code):
        try:
            return int(code()) & 0xFFFFFFFF
        except (TypeError, ValueError):
            pass
    text = str(exc)
    return next((status for status in (STATUS_PASSWORD_MUST_CHANGE, STATUS_PASSWORD_EXPIRED) if name(status) in text or f"0x{status:08X}".lower() in text.lower()), None)


def _open_samr_channel(cfg: ChangeConfig) -> Channel:
    """Open the SAMR channel as the bind identity, falling back to a null session for an expired password.

    A change is the legitimate way to clear an expired password, but the authenticated bind itself fails
    first (STATUS_PASSWORD_MUST_CHANGE / STATUS_PASSWORD_EXPIRED). The buffer-based changes prove the old
    secret in the request, so they run over a null session ([MS-SAMR] 3.1.5.10.3); we retry the bind that
    way. The handle-based DES change cannot, so it is reported clearly instead.
    """
    try:
        return open_channel(cfg.target, cfg.bind, samr.SAMR_UUID, samr.SAMR_PIPE, cfg.transport)
    except (SessionError, DCERPCException) as exc:
        if _bind_status(exc) not in (STATUS_PASSWORD_MUST_CHANGE, STATUS_PASSWORD_EXPIRED):
            raise
        if cfg.method not in _BUFFER_CHANGE_METHODS:
            msg = f"the account password is expired; it can only be changed over a null session by a buffer-based method (samr-aes/rc4/oem/diag), not {cfg.method.value}"
            raise MethodUnavailable(msg) from exc
        LOG.warning("the account password is expired; retrying the SAMR bind over a null session")
        anonymous = BindIdentity(user="", domain="", password="")
        return open_channel(cfg.target, anonymous, samr.SAMR_UUID, samr.SAMR_PIPE, cfg.transport)


def _run_samr_change(cfg: ChangeConfig) -> tuple[ChangeMethod, int, dict[str, str]]:
    """Open a SAMR channel and run the requested (or AUTO-selected) SAMR change."""
    channel = _open_samr_channel(cfg)
    try:
        if cfg.method is not ChangeMethod.AUTO:
            return cfg.method, *_samr_change_once(channel.dce, cfg, cfg.method)
        return _auto_samr_change(channel.dce, cfg)
    finally:
        channel.close()


def _auto_samr_change(dce: DCERPC_v5, cfg: ChangeConfig) -> tuple[ChangeMethod, int, dict[str, str]]:
    """AUTO change: a SamrConnect5 SupportedFeatures preflight picks AES vs RC4 deterministically.

    When the DC explicitly does not advertise the AES buffer we go straight to RC4; otherwise we try the
    AES change and keep the fault-based fallback (MethodUnavailable / STATUS_NOT_SUPPORTED) as a safety net.
    """
    if samr.supports_aes(dce) is False:
        LOG.info("DC does not advertise the AES password buffer (SamrConnect5); using the RC4 change")
        return ChangeMethod.SAMR_RC4, *_samr_change_once(dce, cfg, ChangeMethod.SAMR_RC4)
    try:
        status, extra = _samr_change_once(dce, cfg, ChangeMethod.SAMR_AES)
    except MethodUnavailable:
        LOG.info("AES change unavailable on this DC; falling back to the RC4 change")
        return ChangeMethod.SAMR_RC4, *_samr_change_once(dce, cfg, ChangeMethod.SAMR_RC4)
    if status == STATUS_NOT_SUPPORTED:
        LOG.info("AES change returned STATUS_NOT_SUPPORTED; falling back to the RC4 change")
        return ChangeMethod.SAMR_RC4, *_samr_change_once(dce, cfg, ChangeMethod.SAMR_RC4)
    return ChangeMethod.SAMR_AES, status, extra


def _run_netlogon_change(cfg: ChangeConfig) -> tuple[ChangeMethod, int, dict[str, str]]:
    """Run a machine/trust change: the AUTO machine ladder, or one explicitly named netlogon method."""
    if cfg.method is ChangeMethod.AUTO:
        return _auto_machine_change(cfg)
    runner = netlogon.change_aes if cfg.method is ChangeMethod.NETLOGON_AES else netlogon.change_des
    try:
        status = runner(cfg.target, cfg.netbios, cfg.target.user, cfg.account, cfg.require_new_password(), cfg.old)
    except MethodUnavailable as exc:
        LOG.info("%s unavailable: %s", cfg.method.value, exc)
        return cfg.method, STATUS_UNSUCCESSFUL, {"detail": str(exc)}
    return cfg.method, status, {}


def _samr_aes_change_on_channel(cfg: ChangeConfig) -> tuple[int, dict[str, str]]:
    """Run the SAMR AES cleartext change over a fresh SAMR channel (the machine-AUTO middle rung)."""
    channel = _open_samr_channel(cfg)
    try:
        return _samr_change_once(channel.dce, cfg, ChangeMethod.SAMR_AES)
    finally:
        channel.close()


def _auto_machine_change(cfg: ChangeConfig) -> tuple[ChangeMethod, int, dict[str, str]]:
    """Machine/trust AUTO ladder, taking the first rung that applies.

    Prefer the native netlogon AES change (the secure-channel rotation a domain member runs for itself).
    When that is unavailable, a *machine* account -- being a user-class object -- accepts the SAMR AES
    cleartext change, which hands the DC the plaintext so it regenerates every Kerberos key: a stronger
    result than the legacy DES OWF. Trust accounts are not SAMR-changeable that way, so they skip that
    rung. The netlogon DES change is the final fallback for the oldest DCs.
    """
    try:
        return ChangeMethod.NETLOGON_AES, netlogon.change_aes(cfg.target, cfg.netbios, cfg.target.user, cfg.account, cfg.require_new_password(), cfg.old), {}
    except MethodUnavailable as exc:
        LOG.info("netlogon-aes unavailable (%s); trying the SAMR AES cleartext change", exc)
    if cfg.account is AccountKind.MACHINE:
        try:
            status, extra = _samr_aes_change_on_channel(cfg)
        except (MethodUnavailable, SessionError, DCERPCException) as exc:
            LOG.info("samr-aes fallback unavailable (%s); falling back to netlogon-des", exc)
        else:
            return ChangeMethod.SAMR_AES, status, extra
    try:
        return ChangeMethod.NETLOGON_DES, netlogon.change_des(cfg.target, cfg.netbios, cfg.target.user, cfg.account, cfg.require_new_password(), cfg.old), {}
    except MethodUnavailable as exc:
        return ChangeMethod.NETLOGON_DES, STATUS_UNSUCCESSFUL, {"detail": str(exc)}


# Legacy RC4/LM change methods kept only for completeness against old hosts. Each is discouraged and broke
# in a specific way during live testing, so selecting one explicitly emits an up-front warning. They all
# depend on a stored LM hash, which is off by default since Windows Vista / Server 2008 (NoLmHash).
_LEGACY_CHANGE_WARNINGS: dict[ChangeMethod, str] = {
    ChangeMethod.SAMR_OEM: "samr-oem is a legacy RC4/LM method; avoid it. It needs the target to store an LM hash (off by default since Windows Vista / Server 2008) and a new password of 14 characters or fewer; without a stored LM hash it fails with STATUS_WRONG_PASSWORD. Prefer samr-aes.",
    ChangeMethod.RAP: "rap (NetUserPasswordSet2, opcode 115) is obsolete and LM-only; do not use it. It needs SMB1 (gone on modern Windows) and, where it runs, sets only the LM hash and blanks the NT hash, breaking NTLM and Kerberos logon. Prefer samr-aes or kpasswd.",
    ChangeMethod.RAP_OEM: "rap-oem (SamOEMChangePasswordUser2, opcode 214) is a legacy RC4/LM method; avoid it. It needs an SMB1 host that stores an LM hash and a new password of 14 characters or fewer. Prefer samr-aes.",
}


def _warn_if_legacy(method: ChangeMethod) -> None:
    """Warn before running a discouraged legacy change method, naming the pitfalls seen in testing."""
    warning = _LEGACY_CHANGE_WARNINGS.get(method)
    if warning is not None:
        LOG.warning(warning)


def _run_change(cfg: ChangeConfig) -> Outcome:
    """Dispatch the change by account kind and method, returning a formatted-ready outcome."""
    # The legacy SAMR/RAP methods only apply to user-class accounts; machine/trust always route to netlogon.
    if cfg.account not in (AccountKind.MACHINE, AccountKind.TRUST):
        _warn_if_legacy(cfg.method)
    if cfg.account in (AccountKind.MACHINE, AccountKind.TRUST):
        method, status, extra = _run_netlogon_change(cfg)
    elif cfg.method is ChangeMethod.KPASSWD:
        method, status, extra = ChangeMethod.KPASSWD, kpasswd.change(cfg.target, cfg.target.user, cfg.target.domain, cfg.require_new_password(), cfg.old), {}
    elif cfg.method is ChangeMethod.LDAP:
        status = ldap.change(cfg.target, cfg.bind, cfg.target.user, cfg.old.password, cfg.require_new_password(), use_ldaps=cfg.use_ldaps)
        method, extra = ChangeMethod.LDAP, {}
    elif cfg.method is ChangeMethod.RAP:
        method, status, extra = ChangeMethod.RAP, rap.change(cfg.target, cfg.target.user, cfg.old, cfg.require_new_password()), {}
    elif cfg.method is ChangeMethod.RAP_OEM:
        method, status, extra = ChangeMethod.RAP_OEM, rap.change_oem(cfg.target, cfg.target.user, cfg.old, cfg.require_new_password()), {}
    else:
        method, status, extra = _run_samr_change(cfg)
    return Outcome(operation="change", method=method.value, target=cfg.label, dc=cfg.target.dc, status=status, extra=extra)


def _build_config(args: argparse.Namespace) -> ChangeConfig:
    """Resolve parsed arguments into a ChangeConfig, including the bind identity and old secret."""
    # --target-domain is required; the DC and the auth-as domain both default to it when omitted.
    domain = args.target_domain
    dc = args.dc or domain
    target = Target(domain=domain, user=args.target_user, dc=dc)

    lm_hash, nt_hash = parse_hash_pair(args.target_old_hash)
    # The change proves a current secret. With neither a password nor a hash on the command line, prompt
    # for the password (the ldap change can run without proving the old secret, so it is exempt).
    old_password = args.target_old_password
    if old_password is None and nt_hash is None and args.method != ChangeMethod.LDAP.value:
        old_password = prompt_password(f"Current password for {target.user}")
    old = Secret(password=old_password, nt_hash=nt_hash, lm_hash=lm_hash)

    # A new NT hash can only be set by the DES change (opnum 38), which writes the raw OWF; pin the method
    # to it (or reject a conflicting explicit method). A cleartext new password is prompted for when absent.
    new_lm_hash, new_nt_hash = parse_hash_pair(args.target_new_hash)
    new_password = args.target_new_password
    if new_password is None and new_nt_hash is None:
        new_password = prompt_password(f"New password for {target.user}")
    method = ChangeMethod(args.method)
    if new_nt_hash is not None:
        if method is ChangeMethod.AUTO:
            method = ChangeMethod.SAMR_DES
        elif method is not ChangeMethod.SAMR_DES:
            msg = "a new NT hash can only be set by the DES change; use --method samr-des (or leave the default)"
            raise ValueError(msg)

    # Without --auth-as-user the change authenticates as the target itself, using the old secret it just
    # proved; --auth-as-* binds the SAMR/LDAP session as a different (usually privileged) principal.
    if args.auth_as_user:
        _, auth_nt = parse_hash_pair(args.auth_as_hash)
        auth_password = args.auth_as_password
        # With Kerberos the bind can come from the ticket cache, so only prompt for a password under NTLM.
        if auth_password is None and auth_nt is None and not args.kerberos:
            auth_password = prompt_password(f"Password for {args.auth_as_user}")
        bind = BindIdentity(user=args.auth_as_user, domain=args.auth_as_domain or domain, password=auth_password or "", nt_hash=auth_nt, use_kerberos=args.kerberos)
    else:
        bind = BindIdentity(user=target.user, domain=domain, password=old_password or "", nt_hash=nt_hash, use_kerberos=args.kerberos)

    netbios = args.netbios or domain.split(".")[0].upper()
    return ChangeConfig(
        target=target,
        new_password=new_password,
        new_nt_hash=new_nt_hash,
        new_lm_hash=new_lm_hash,
        old=old,
        account=AccountKind(args.account),
        method=method,
        transport=TransportKind(args.transport),
        bind=bind,
        netbios=netbios,
        use_ldaps=args.ldaps,
        output=OutputFormat(args.format),
    )


_DESCRIPTION = """\
Change an Active Directory account password by proving its current secret.

A change requires no privilege on the target: it proves knowledge of the current password, or its NT hash
for a pass-the-hash change. passwolf change implements every Windows change method over SAMR, Kerberos, LDAP,
Netlogon, and the legacy RAP path, including the AES SAMR change (opnum 73) that impacket lacks and that
Windows Server 2025 requires once it disables the legacy RC4 changes. AUTO selects the strongest method the
DC accepts and falls back only when a method is genuinely unavailable."""

_EPILOG = """\
examples:
  # change your own password; AUTO picks the strongest method the DC accepts
  passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

  # pass-the-hash change pinned to the AES SAMR change
  passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-hash <NTHASH> --target-new-password 'NewPass1!' --method samr-aes

  # change over the Kerberos change protocol
  passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!' --method kpasswd

  # rotate a machine account secret over the Netlogon secure channel
  passwolf change --target-domain corp.local --target-user 'WS01$' --dc dc01.corp.local --account machine --target-old-password 'OldMachinePw' --target-new-password 'NewMachinePw'

  # set the new password directly by NT hash (DES change; bypasses policy, no privilege)
  passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-hash <NTHASH>

note: an expired or must-change-at-next-logon password is changed over a null session automatically; this
works only for the buffer-based methods (samr-aes/rc4/oem/diag), not the handle-based DES change.

exit status: 0 on success, 1 on a failed or unavailable method, 2 on a usage error.

note: credentials passed on the command line may be visible to other local users via the process list.

documentation: https://strongwind1.github.io/passwolf/"""


def _build_parser() -> argparse.ArgumentParser:
    """Build the passwolf change command line."""
    parser = argparse.ArgumentParser(
        prog="passwolf change",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    target = parser.add_argument_group("the account to change")
    target.add_argument("--target-user", required=True, metavar="NAME", help="(required) the account whose password you want to change (a computer or trust account ends with a $)")
    target.add_argument("--target-domain", required=True, metavar="NAME", help="(required) the Active Directory domain the account belongs to, such as corp.local")

    new = parser.add_argument_group("the new secret (a password, or a hash for the DES change)")
    new_secret = new.add_mutually_exclusive_group()
    new_secret.add_argument("--target-new-password", metavar="PASS", help="(required) the new password to set on the account; if you omit both this and --target-new-hash, you are prompted for it without echo")
    new_secret.add_argument("--target-new-hash", metavar="[LM:]NT", help="set the new password directly by NT hash; only the DES change can do this (it pins --method samr-des), and it bypasses policy, drops the Kerberos keys, and flags the password expired")

    current = parser.add_argument_group("proof you may change it (give --target-old-password or --target-old-hash; prompted if you give neither, except with --method ldap)")
    current.add_argument("--target-old-password", metavar="PASS", help="the account's current password; prompted for if you supply neither this nor --target-old-hash")
    current.add_argument("--target-old-hash", metavar="[LM:]NT", help="the account's current NT hash, to change the password without knowing the plain text")

    server = parser.add_argument_group("the server to connect to")
    server.add_argument("--dc", metavar="HOST", help="(optional) the domain controller to connect to, by hostname or IP address; defaults to the --target-domain name")

    authas = parser.add_argument_group("sign in as someone else (all optional; defaults to the account being changed)")
    authas.add_argument("--auth-as-user", metavar="NAME", help="a different account to authenticate the SAMR or LDAP session as")
    authas.add_argument("--auth-as-password", metavar="PASS", help="that account's password; prompted for if you give --auth-as-user with neither this nor --auth-as-hash")
    authas.add_argument("--auth-as-hash", metavar="[LM:]NT", help="that account's NT hash, to sign in without its plain-text password")
    authas.add_argument("--auth-as-domain", metavar="NAME", help="that account's domain; defaults to the --target-domain name")
    authas.add_argument("-k", "--kerberos", action="store_true", help="authenticate the bind with Kerberos instead of NTLM; uses the ticket cache named by KRB5CCNAME, or fetches a ticket with the password or hash")

    kind = parser.add_argument_group("account kind")
    kind.add_argument("--account", choices=[k.value for k in AccountKind], default=AccountKind.USER.value, help="what kind of account this is: a normal user, a computer, or a domain trust (default user)")

    selection = parser.add_argument_group("how to make the change")
    selection.add_argument("--method", choices=[m.value for m in ChangeMethod], default=ChangeMethod.AUTO.value, metavar="METHOD", help="which technique to use; leave as 'auto' (the default) to let the tool pick the strongest one the server accepts. one of: " + ", ".join(m.value for m in ChangeMethod))
    selection.add_argument("--transport", choices=[t.value for t in TransportKind], default=TransportKind.SMB.value, help="how to reach the server for the SAMR methods: over an SMB named pipe or a direct TCP connection (default smb)")
    selection.add_argument("--netbios", metavar="NAME", help="the short (NetBIOS) domain name, used only for computer and trust accounts; taken from the domain when left unset")
    selection.add_argument("--ldaps", action="store_true", help="for the LDAP method, connect with encryption on port 636 instead of port 389")

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=[f.value for f in OutputFormat], default=OutputFormat.PRETTY.value, help="how to print the result: plain text, JSON, or a formatted box (default pretty)")
    output.add_argument("-v", "--verbose", action="store_true", help="print detailed logging for troubleshooting")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the passwolf change console script."""
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    try:
        cfg = _build_config(args)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2

    try:
        outcome = _run_change(cfg)
    except MethodUnavailable as exc:
        LOG.error("method unavailable: %s", exc)
        return 1
    except OperationFailed as exc:
        outcome = Outcome(operation="change", method=cfg.method.value, target=cfg.label, dc=cfg.target.dc, status=STATUS_UNSUCCESSFUL, extra={"detail": str(exc)})
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
