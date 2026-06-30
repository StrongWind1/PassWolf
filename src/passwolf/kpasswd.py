"""Kerberos password change and set (RFC 3244, MS-KILE 3.1.5.12).

Both the change and the set are sent on the wire with framing version 0xFF80; the change authenticates as
the target and proves the current secret, while the set authenticates as a privileged caller and names a
target. The two are distinguished by the absence or presence of targname/targrealm in ChangePasswdData,
not by the version field (0x0001 is only the value the server stamps on its reply). impacket implements
both at the protocol layer, so this module adapts them to the passwolf method contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.krb5 import kpasswd
from impacket.krb5.kerberosv5 import KerberosError

from .errors import OperationFailed
from .nterror import STATUS_SUCCESS

if TYPE_CHECKING:
    from .model import Secret, Target


def _old_nt_hex(secret: Secret) -> str:
    """Render an NT hash for kpasswd's hash credential, or empty when only a password is available."""
    return secret.nt_hash.hex() if secret.nt_hash is not None else ""


def change(target: Target, user: str, domain: str, new_password: str, old: Secret) -> int:
    """Change the caller's own password via the Kerberos change protocol (kadmin/changepw)."""
    try:
        kpasswd.changePassword(
            user,
            domain or target.domain,
            new_password,
            oldPasswd=old.password or "",
            oldNthash=_old_nt_hex(old),
            kdcHost=target.dc,
            kpasswdHost=target.dc,
        )
    except (KerberosError, kpasswd.KPasswdError) as exc:
        msg = f"kpasswd change failed: {exc}"
        raise OperationFailed(msg) from exc
    return STATUS_SUCCESS


def reset(target: Target, caller_user: str, caller_domain: str, caller_secret: Secret, target_user: str, target_domain: str, new_password: str) -> int:
    """Reset a target account's password via the Kerberos set protocol, as a privileged caller."""
    try:
        kpasswd.setPassword(
            caller_user,
            caller_domain or target.domain,
            target_user,
            target_domain or target.domain,
            new_password,
            oldPasswd=caller_secret.password or "",
            oldNthash=_old_nt_hex(caller_secret),
            kdcHost=target.dc,
            kpasswdHost=target.dc,
        )
    except (KerberosError, kpasswd.KPasswdError) as exc:
        msg = f"kpasswd set failed: {exc}"
        raise OperationFailed(msg) from exc
    return STATUS_SUCCESS
