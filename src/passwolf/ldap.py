# SPDX-License-Identifier: Apache-2.0
"""LDAP password change and reset over unicodePwd ([MS-ADTS] 3.1.1.3.1.5).

A change is one Modify that deletes the old quoted value and adds the new one; a reset is one Modify
that replaces the value. Both require a confidential channel: passwolf defaults to plain LDAP on 389
with a SASL sign-and-seal bind (no certificate needed), and only uses LDAPS when asked, which is the
decisive correctness fix over impacket's changepasswd.py that hardcodes ldaps://.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from impacket.ldap import ldapasn1
from impacket.ldap.ldap import LDAPConnection, LDAPSearchError

from .errors import MethodUnavailable, OperationFailed
from .nterror import STATUS_SUCCESS
from .transport import kerberos_login_args

if TYPE_CHECKING:
    from .model import Target
    from .transport import BindIdentity

# impacket LDAP modify operation codes.
_OP_ADD = 0
_OP_DELETE = 1
_OP_REPLACE = 2


def _base_dn(domain: str) -> str:
    """Build the default naming context DN from a DNS domain (corp.local -> dc=corp,dc=local)."""
    return ",".join(f"dc={part}" for part in domain.split(".") if part)


def _connect(target: Target, identity: BindIdentity, *, use_ldaps: bool) -> LDAPConnection:
    """Bind to the DC over LDAP (sealed 389) or LDAPS, using Kerberos, a password, or pass-the-hash."""
    scheme = "ldaps" if use_ldaps else "ldap"
    connection = LDAPConnection(f"{scheme}://{target.dc}", baseDN=_base_dn(identity.domain), dstIp=target.dc)
    if identity.use_kerberos:
        connection.kerberosLogin(**kerberos_login_args(identity, target.dc))
    else:
        nt_hex = identity.nt_hash.hex() if identity.nt_hash is not None else ""
        connection.login(user=identity.user, password=identity.password, domain=identity.domain, nthash=nt_hex)
    return connection


def _resolve_dn(connection: LDAPConnection, sam_account: str) -> str:
    """Resolve a sAMAccountName to its distinguishedName, raising when it cannot be found."""
    results = connection.search(searchFilter=f"(sAMAccountName={sam_account})", attributes=["distinguishedName"])
    for entry in results:
        if isinstance(entry, ldapasn1.SearchResultEntry):
            return entry["objectName"].asOctets().decode("utf-8")
    msg = f"could not resolve a distinguishedName for {sam_account}"
    raise OperationFailed(msg)


def _quoted(password: str) -> bytes:
    """Encode a password as the quoted UTF-16LE octet string unicodePwd expects."""
    return f'"{password}"'.encode("utf-16-le")


def change(target: Target, identity: BindIdentity, target_user: str, old_password: str | None, new_password: str, *, use_ldaps: bool) -> int:
    """Change unicodePwd with a delete-old + add-new Modify (needs the cleartext old password)."""
    if old_password is None:
        msg = "the LDAP change needs the cleartext old password to form the delete value"
        raise MethodUnavailable(msg)
    connection = _connect(target, identity, use_ldaps=use_ldaps)
    dn = _resolve_dn(connection, target_user)
    changes = {"unicodePwd": [(_OP_DELETE, [_quoted(old_password)]), (_OP_ADD, [_quoted(new_password)])]}
    try:
        succeeded = connection.modify(dn, changes)
    except LDAPSearchError as exc:
        msg = f"LDAP change failed: {exc}"
        raise OperationFailed(msg) from exc
    if not succeeded:
        msg = "LDAP change returned failure"
        raise OperationFailed(msg)
    return STATUS_SUCCESS


def reset(target: Target, identity: BindIdentity, target_user: str, new_password: str, *, use_ldaps: bool) -> int:
    """Reset unicodePwd with a single replace Modify (privileged, no old password)."""
    connection = _connect(target, identity, use_ldaps=use_ldaps)
    dn = _resolve_dn(connection, target_user)
    changes = {"unicodePwd": [(_OP_REPLACE, [_quoted(new_password)])]}
    try:
        succeeded = connection.modify(dn, changes)
    except LDAPSearchError as exc:
        msg = f"LDAP reset failed: {exc}"
        raise OperationFailed(msg) from exc
    if not succeeded:
        msg = "LDAP reset returned failure"
        raise OperationFailed(msg)
    return STATUS_SUCCESS
