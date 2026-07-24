# SPDX-License-Identifier: Apache-2.0
"""Read-only password-policy harvesting, one function per wire method.

This module gathers the effective and configured password policy over every channel a domain controller
exposes it on: the SAMR domain-query classes and the handle-light / per-user getters, the undocumented
opnum-63 change-failure oracle (read-safe here, never applying a change), the Kerberos kpasswd SOFTERROR
blob, the LDAP domain head and fine-grained PSO objects, and the SYSVOL ``GptTmpl.inf`` configured intent.
It reuses the shared crypto (:mod:`passwolf.crypto`) and NDR types (:mod:`passwolf.ndr`) but imports nothing
from the change/reset modules, keeping reading a separate concern with no path that can mutate a password.
"""

from __future__ import annotations

import configparser
import io
import struct
from typing import TYPE_CHECKING

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.krb5 import kpasswd as ik
from impacket.krb5.asn1 import AS_REP, KRB_PRIV, EncKrbPrivPart
from impacket.krb5.constants import PrincipalNameType
from impacket.krb5.crypto import Key, get_random_bytes
from impacket.krb5.kerberosv5 import getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, Ticket
from impacket.ldap import ldapasn1
from impacket.ldap.ldap import LDAPConnection, LDAPSearchError
from impacket.smbconnection import SessionError, SMBConnection
from pyasn1.codec.der import decoder

from . import crypto, ndr
from .constants import (
    DOMAIN_LOCKOUT_INFORMATION,
    DOMAIN_LOGOFF_INFORMATION,
    DOMAIN_PASSWORD_INFORMATION,
    PASSWORD_SETTINGS_CONTAINER_RDN,
    UF_LOCKOUT,
    UF_PASSWORD_EXPIRED,
    USER_READ_GENERAL,
)
from .errors import MethodUnavailable, OperationFailed
from .nterror import STATUS_ACCESS_DENIED
from .policymodel import (
    GptTmplPolicy,
    PasswordPolicy,
    PsoPolicy,
    complexity_from_properties,
    reversible_from_properties,
    ticks_to_days,
    ticks_to_minutes,
)
from .transport import kerberos_login_args

if TYPE_CHECKING:
    from impacket.dcerpc.v5.rpcrt import DCERPC_v5
    from impacket.dcerpc.v5.samr import OLD_LARGE_INTEGER

    from .model import Secret, Target
    from .transport import BindIdentity

# A new password guaranteed to violate any real domain policy (too short, and zero complexity classes),
# so the opnum-63 and kpasswd oracles always draw STATUS_PASSWORD_RESTRICTION / SOFTERROR and the probed
# account is never actually changed.
_POLICY_PROBE_PASSWORD = "\x01\x01"

# A kpasswd age (already in days) at or beyond this magnitude is the int64 never-sentinel reinterpreted.
_KPASSWD_NEVER_DAYS = 10_000_000

# SAMR transport binding, shared by every SAMR read (mirrors passwolf.samr without importing it).
SAMR_PIPE = r"\samr"
SAMR_UUID = samr.MSRPC_UUID_SAMR


# --- 64-bit interval helpers ([MS-SAMR] 2.2.2.2 OLD_LARGE_INTEGER, delta time) ---
def _old_li_ticks(large_integer: OLD_LARGE_INTEGER) -> int:
    """Read a split OLD_LARGE_INTEGER (LowPart/HighPart) as one signed 100-nanosecond tick count."""
    high = int(large_integer["HighPart"])
    low = int(large_integer["LowPart"]) & 0xFFFFFFFF
    return (high << 32) | low


def _hyper_signed(value: int) -> int:
    """Reinterpret an unsigned NDRHYPER (LARGE_INTEGER) as a signed 64-bit tick count."""
    unsigned = int(value) & 0xFFFFFFFFFFFFFFFF
    return unsigned - (1 << 64) if unsigned >= (1 << 63) else unsigned


def _ticks_to_seconds(ticks: int | None) -> float | None:
    """Convert a signed 100ns interval to seconds (for the force-logoff field), inf for the never sentinel."""
    days = ticks_to_days(ticks)
    return None if days is None else (days * 86400)


# --- SAMR: connect chain and domain-query classes ([MS-SAMR] 3.1.5.5) ---
def open_domain_handle(dce: DCERPC_v5, access: int = MAXIMUM_ALLOWED) -> tuple[object, object, str]:
    """Resolve the account domain and open a domain handle, returning (handle, domain SID, domain name).

    Mirrors the standard SamrConnect -> EnumerateDomains -> LookupDomain -> OpenDomain chain so the
    query classes have a handle. Kept local to the read module so reading never imports the change path.
    """
    server_handle = samr.hSamrConnect(dce)["ServerHandle"]
    domains = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"]
    domain_name = next(d["Name"] for d in domains if d["Name"].lower() != "builtin")
    domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)["DomainId"]
    domain_handle = samr.hSamrOpenDomain(dce, server_handle, access, domain_sid)["DomainHandle"]
    return domain_handle, domain_sid, domain_name


def _query_domain(dce: DCERPC_v5, domain_handle: object, info_class: int) -> samr.SAMPR_DOMAIN_INFO_BUFFER:
    """Query one DOMAIN_INFORMATION_CLASS via opnum 46, falling back to opnum 8 on an RPC fault.

    Both opnums return the same SAMPR_DOMAIN_INFO_BUFFER union; opnum 46 is the modern call and opnum 8
    the legacy one, so trying 46 first and 8 on fault covers every server version.
    """
    try:
        return samr.hSamrQueryInformationDomain2(dce, domain_handle, info_class)["Buffer"]
    except DCERPCException:
        return samr.hSamrQueryInformationDomain(dce, domain_handle, info_class)["Buffer"]


def samr_password_policy(dce: DCERPC_v5, domain_handle: object) -> PasswordPolicy:
    """Build the default-domain policy from SAMR classes 1 (password), 12 (lockout), and 3 (force-logoff).

    Class 1 (DomainPasswordInformation) is required and raises through if denied; the lockout and
    force-logoff classes are best-effort so a partial read still returns the password fields.
    """
    password = _query_domain(dce, domain_handle, DOMAIN_PASSWORD_INFORMATION)["Password"]
    properties = int(password["PasswordProperties"])
    lockout_threshold: int | None = None
    lockout_duration: float | None = None
    lockout_window: float | None = None
    force_logoff: float | None = None
    try:  # class 12: lockout duration/window/threshold (best-effort)
        lockout = _query_domain(dce, domain_handle, DOMAIN_LOCKOUT_INFORMATION)["Lockout"]
        lockout_threshold = int(lockout["LockoutThreshold"])
        lockout_duration = ticks_to_minutes(_hyper_signed(lockout["LockoutDuration"]))
        lockout_window = ticks_to_minutes(_hyper_signed(lockout["LockoutObservationWindow"]))
    except DCERPCException:
        pass
    try:  # class 3: force-logoff interval, reported in seconds (best-effort)
        logoff = _query_domain(dce, domain_handle, DOMAIN_LOGOFF_INFORMATION)["Logoff"]
        force_logoff = _ticks_to_seconds(_old_li_ticks(logoff["ForceLogoff"]))
    except DCERPCException:
        pass
    return PasswordPolicy(
        source="samr-query (opnum 46)",
        min_password_length=int(password["MinPasswordLength"]),
        password_history_length=int(password["PasswordHistoryLength"]),
        password_properties_raw=properties,
        complexity_enabled=complexity_from_properties(properties),
        reversible_encryption=reversible_from_properties(properties),
        max_password_age_days=ticks_to_days(_old_li_ticks(password["MaxPasswordAge"])),
        min_password_age_days=ticks_to_days(_old_li_ticks(password["MinPasswordAge"])),
        lockout_threshold=lockout_threshold,
        lockout_duration_minutes=lockout_duration,
        lockout_observation_window_minutes=lockout_window,
        force_logoff_seconds=force_logoff,
    )


def samr_get_domain_password_information(dce: DCERPC_v5) -> PasswordPolicy:
    """SamrGetDomainPasswordInformation (opnum 56): the handle-light minimum-length + properties read.

    Needs no domain handle (the server resolves the account domain itself), so it is reachable before any
    OpenDomain and is the lightest unauthenticated policy probe. It carries only length and properties.
    """
    info = samr.hSamrGetDomainPasswordInformation(dce)["PasswordInformation"]
    properties = int(info["PasswordProperties"])
    return PasswordPolicy(
        source="samr-getdompwinfo (opnum 56)",
        min_password_length=int(info["MinPasswordLength"]),
        password_properties_raw=properties,
        complexity_enabled=complexity_from_properties(properties),
        reversible_encryption=reversible_from_properties(properties),
    )


def samr_get_user_password_information(dce: DCERPC_v5, domain_handle: object, user: str) -> PasswordPolicy:
    """SamrGetUserDomainPasswordInformation (opnum 44): the per-user, PSO-resolved minimum-length read.

    Opens the user with USER_READ_GENERAL and asks for the policy the server considers effective for that
    user, so a fine-grained password policy (PSO) bound to the user is reflected here, unlike the default
    classes. Carries only length and properties.
    """
    rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [user])["RelativeIds"]["Element"][0]
    user_handle = samr.hSamrOpenUser(dce, domain_handle, USER_READ_GENERAL, rid)["UserHandle"]
    info = samr.hSamrGetUserDomainPasswordInformation(dce, user_handle)["PasswordInformation"]
    properties = int(info["PasswordProperties"])
    return PasswordPolicy(
        source=f"samr-getusrpwinfo (opnum 44, effective for {user})",
        scope="PSO",
        min_password_length=int(info["MinPasswordLength"]),
        password_properties_raw=properties,
        complexity_enabled=complexity_from_properties(properties),
        reversible_encryption=reversible_from_properties(properties),
    )


# --- SAMR opnum-63 change-failure oracle (read-safe) ([MS-SAMR] leaked samrpc.idl) ---
def _oracle_old_nt(old: Secret) -> bytes:
    """Resolve the probed account's NT hash from its cleartext password or a supplied NT hash."""
    if old.nt_hash is not None:
        return old.nt_hash
    if old.password is not None:
        return crypto.nt_owf(old.password)
    msg = "the opnum-63 oracle needs the probed user's current password or NT hash"
    raise MethodUnavailable(msg)


def samr_oracle_policy(dce: DCERPC_v5, user: str, old: Secret) -> tuple[PasswordPolicy, str | None]:
    """SamrUnicodeChangePasswordUser3 (opnum 63) used purely to read the effective policy, never to change.

    A deliberately policy-violating new password is submitted, so the server returns
    STATUS_PASSWORD_RESTRICTION and fills the effective DOMAIN_PASSWORD_INFORMATION plus the extended
    failure reason without ever applying the change (leaked user.c:11565-11589). The policy is the one the
    server considers effective for ``user`` (PSO-aware). The call uses call()/recv() so impacket's status
    auto-raise does not discard the diagnostics body, the same way the change tool's diagnostic path does.
    Server 2025 refuses opnum 63 with STATUS_ACCESS_DENIED (the CVE-2021-33757 legacy-RC4 gate); that
    surfaces as the method being unavailable.
    """
    old_nt = _oracle_old_nt(old)
    new_nt = crypto.nt_owf(_POLICY_PROBE_PASSWORD)
    request = ndr.SamrUnicodeChangePasswordUser3()
    request["ServerName"] = "\x00"
    request["UserName"] = user
    request["NewPasswordEncryptedWithOldNt"]["Buffer"] = crypto.build_rc4_password_buffer(_POLICY_PROBE_PASSWORD, old_nt)
    request["OldNtOwfPasswordEncryptedWithNewNt"] = crypto.des_owf_encrypt(old_nt, new_nt)
    request["LmPresent"] = 0
    request["NewPasswordEncryptedWithOldLm"] = NULL
    request["OldLmOwfPasswordEncryptedWithNewLmOrNt"] = NULL
    request["AdditionalData"] = NULL
    try:
        dce.call(request.opnum, request)
        stub = dce.recv()
    except DCERPCException as exc:
        raise MethodUnavailable(str(exc)) from exc
    response = ndr.SamrUnicodeChangePasswordUser3Response(stub)
    policy = response["EffectivePasswordPolicy"]
    if isinstance(policy, bytes):  # null referent: the server filled no policy block
        status = int(response["ErrorCode"]) & 0xFFFFFFFF
        if status == STATUS_ACCESS_DENIED:  # Server 2025 gates the legacy RC4 opnum 63 (CVE-2021-33757)
            msg = "opnum 63 is refused (STATUS_ACCESS_DENIED); use kpasswd for the policy oracle on Server 2025"
            raise MethodUnavailable(msg)
        msg = f"opnum 63 returned no effective-policy block (status 0x{status:08X}; the probe drew no password restriction)"
        raise OperationFailed(msg)
    properties = int(policy["PasswordProperties"])
    record = PasswordPolicy(
        source=f"samr-diag oracle (opnum 63, effective for {user})",
        scope="PSO",
        min_password_length=int(policy["MinPasswordLength"]),
        password_history_length=int(policy["PasswordHistoryLength"]),
        password_properties_raw=properties,
        complexity_enabled=complexity_from_properties(properties),
        reversible_encryption=reversible_from_properties(properties),
        max_password_age_days=ticks_to_days(_old_li_ticks(policy["MaxPasswordAge"])),
        min_password_age_days=ticks_to_days(_old_li_ticks(policy["MinPasswordAge"])),
    )
    change_info = response["PasswordChangeInfo"]
    reason = None if isinstance(change_info, bytes) else str(int(change_info["ExtendedFailureReason"]))
    return record, reason


# --- Kerberos kpasswd SOFTERROR policy blob (RFC 3244; works on Server 2025) ---
def _decode_kpasswd_reply_raw(encoded: bytes, cipher: Key, sub_key: Key) -> tuple[int, bytes]:
    """Decode a kpasswd reply to its (result code, raw user-data) without impacket's string formatting.

    impacket's decodeKPasswdReply pre-formats the SOFTERROR policy into a human string; this thin decoder
    mirrors only its crypto (KRB-PRIV under the subkey, key usage 13) to recover the raw bytes so the
    structured policy can be parsed instead. The KRB-PRIV/EncKrbPrivPart shapes are stable RFC structures.
    """
    header_len = struct.calcsize("!HHH")
    _, _, ap_rep_len = struct.unpack("!HHH", encoded[:header_len])
    krb_priv_encoded = encoded[header_len + ap_rep_len :]
    krb_priv = decoder.decode(krb_priv_encoded, asn1Spec=KRB_PRIV())[0]
    decrypted = cipher.decrypt(sub_key, 13, krb_priv["enc-part"]["cipher"])
    enc_part = decoder.decode(decrypted, asn1Spec=EncKrbPrivPart())[0]
    result = enc_part["user-data"].asOctets()
    return int.from_bytes(result[:2], "big"), result[2:]


def kpasswd_softerror_policy(target: Target, auth_user: str, domain: str, secret: Secret) -> PasswordPolicy:
    """Harvest the password policy from a kpasswd change rejection (SOFTERROR), as the authenticating user.

    Authenticates the supplied account against kadmin/changepw, submits a guaranteed-violating self-change,
    and parses the SOFTERROR policy blob the KDC returns. Unlike the opnum-63 oracle this is not RC4-gated,
    so it works on Server 2025. The policy is effective for ``auth_user`` (PSO-aware). The probed account is
    never changed because the new password always violates policy; an unexpected SUCCESS is reported as a
    failure so the operator can verify the account rather than silently accepting a write.
    """
    principal = Principal(auth_user, type=PrincipalNameType.NT_PRINCIPAL.value)
    nt_hex = secret.nt_hash.hex() if secret.nt_hash is not None else ""
    try:
        tgt, cipher, _, session_key = getKerberosTGT(principal, secret.password or "", domain, "", nt_hex, "", target.dc, serverName=ik.KRB5_KPASSWD_TGT_SPN)
        decoded = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decoded["ticket"])
        sub_key = Key(cipher.enctype, get_random_bytes(cipher.keysize))
        request = ik.createKPasswdRequest(principal, domain, _POLICY_PROBE_PASSWORD, ticket, cipher, session_key, sub_key)
        reply = sendReceive(request, domain, target.dc, ik.KRB5_KPASSWD_PORT)
    except Exception as exc:  # impacket krb5 raises bare exceptions for auth/network failures
        msg = f"kpasswd policy probe could not run: {exc}"
        raise MethodUnavailable(msg) from exc

    result_code, raw = _decode_kpasswd_reply_raw(reply, cipher, sub_key)
    if result_code == ik.KPasswdResultCodes.SUCCESS.value:
        msg = "kpasswd probe unexpectedly succeeded; the probe password may have been applied, verify the account"
        raise OperationFailed(msg)
    if result_code != ik.KPasswdResultCodes.SOFTERROR.value:
        detail = ik.RESULT_MESSAGES.get(result_code, "unknown")
        msg = f"kpasswd returned result code {result_code} ({detail}), no policy blob"
        raise MethodUnavailable(msg)
    try:
        parsed = ik._decodePasswordPolicy(raw)  # noqa: SLF001  # private helper, pinned by a regression test
    except (ValueError, struct.error) as exc:
        msg = "kpasswd SOFTERROR carried no parseable policy blob"
        raise MethodUnavailable(msg) from exc
    return _kpasswd_policy_record(parsed, auth_user)


def _kpasswd_policy_record(parsed: dict[str, object], auth_user: str) -> PasswordPolicy:
    """Map impacket's kpasswd policy dict onto the canonical PasswordPolicy record.

    The kpasswd blob stores the flags as the same DOMAIN_PASSWORD_* bitmask and the ages as positive day
    counts; an age at or beyond ~27,000 years is the int64 never-sentinel reinterpreted, reported as inf.
    """
    flags = parsed.get("flags", [])
    flag_names = [str(flag) for flag in flags] if isinstance(flags, list) else []
    # impacket's PasswordPolicyFlags names map onto the identical DOMAIN_PASSWORD_* bit values.
    kpasswd_flag_bits = {
        "Complex": 0x01,
        "NoAnonChange": 0x02,
        "NoClearChange": 0x04,
        "LockoutAdmins": 0x08,
        "StoreCleartext": 0x10,
        "RefusePasswordChange": 0x20,
    }
    properties = 0
    for name, bit in kpasswd_flag_bits.items():
        if name in flag_names:
            properties |= bit
    return PasswordPolicy(
        source=f"kpasswd-softerror (RFC 3244, effective for {auth_user})",
        scope="PSO",
        min_password_length=int(str(parsed["minLength"])),
        password_history_length=int(str(parsed["history"])),
        max_password_age_days=_kpasswd_age(parsed["maxAge"]),
        min_password_age_days=_kpasswd_age(parsed["minAge"]),
        password_properties_raw=properties,
        complexity_enabled="Complex" in flag_names,
        reversible_encryption="StoreCleartext" in flag_names,
    )


def _kpasswd_age(days: object) -> float:
    """Normalize a kpasswd age (already in days) to inf when it is the never-sentinel magnitude."""
    value = float(str(days))
    return float("inf") if value >= _KPASSWD_NEVER_DAYS else round(value, 4)


# --- LDAP: domain head, PSO objects, resultant PSO, and computed UAC ([MS-ADTS] 3.1.1) ---
def _base_dn(domain: str) -> str:
    """Build the default naming context DN from a DNS domain (corp.local -> dc=corp,dc=local)."""
    return ",".join(f"dc={part}" for part in domain.split(".") if part)


def _ldap_connect(target: Target, identity: BindIdentity, *, use_ldaps: bool) -> LDAPConnection:
    """Bind to the DC over sealed LDAP (389) or LDAPS, with Kerberos, a password, or pass-the-hash."""
    scheme = "ldaps" if use_ldaps else "ldap"
    connection = LDAPConnection(f"{scheme}://{target.dc}", baseDN=_base_dn(identity.domain), dstIp=target.dc)
    if identity.use_kerberos:
        connection.kerberosLogin(**kerberos_login_args(identity, target.dc))
        return connection
    nt_hex = identity.nt_hash.hex() if identity.nt_hash is not None else ""
    connection.login(user=identity.user, password=identity.password, domain=identity.domain, nthash=nt_hex)
    return connection


def _entry_attrs(entry: ldapasn1.SearchResultEntry) -> dict[str, list[bytes]]:
    """Flatten an LDAP SearchResultEntry into a lowercased attribute -> list-of-raw-values map."""
    attrs: dict[str, list[bytes]] = {}
    for attribute in entry["attributes"]:
        name = attribute["type"].asOctets().decode("utf-8").lower()
        attrs[name] = [value.asOctets() for value in attribute["vals"]]
    return attrs


def _attr_int(attrs: dict[str, list[bytes]], name: str) -> int | None:
    """Read one integer-valued attribute (stored as a decimal string), or None when absent."""
    values = attrs.get(name.lower())
    return int(values[0].decode("utf-8")) if values else None


def _attr_str(attrs: dict[str, list[bytes]], name: str) -> str | None:
    """Read one string-valued attribute, or None when absent."""
    values = attrs.get(name.lower())
    return values[0].decode("utf-8") if values else None


def _attr_bool(attrs: dict[str, list[bytes]], name: str) -> bool | None:
    """Read one AD boolean attribute (TRUE/FALSE), or None when absent."""
    value = _attr_str(attrs, name)
    return None if value is None else value.strip().upper() == "TRUE"


def _search(connection: LDAPConnection, base: str, scope: str, ldap_filter: str, attributes: list[str]) -> list[ldapasn1.SearchResultEntry]:
    """Run one LDAP search and return only the SearchResultEntry rows (dropping referrals)."""
    results = connection.search(searchBase=base, scope=ldapasn1.Scope(scope), searchFilter=ldap_filter, attributes=attributes)
    return [entry for entry in results if isinstance(entry, ldapasn1.SearchResultEntry)]


_DOMAIN_HEAD_ATTRS = ["minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge", "pwdProperties", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "forceLogoff"]


def ldap_domain_head(target: Target, identity: BindIdentity, *, use_ldaps: bool) -> PasswordPolicy:
    """Read the default policy straight off the domainDNS object's password attributes ([MS-ADTS] 3.1.1.4).

    These attributes (minPwdLength, pwdProperties, the Interval-typed ages and lockout windows) are the
    canonical default-domain policy and are readable by any authenticated principal, making LDAP the most
    complete single-shot default-policy source.
    """
    connection = _ldap_connect(target, identity, use_ldaps=use_ldaps)
    base = _base_dn(identity.domain)
    entries = _search(connection, base, "baseObject", "(objectClass=*)", _DOMAIN_HEAD_ATTRS)
    if not entries:
        msg = "LDAP returned no domain head object"
        raise OperationFailed(msg)
    attrs = _entry_attrs(entries[0])
    properties = _attr_int(attrs, "pwdProperties")
    force_logoff = _attr_int(attrs, "forceLogoff")
    return PasswordPolicy(
        source="ldap-domain-head",
        min_password_length=_attr_int(attrs, "minPwdLength"),
        password_history_length=_attr_int(attrs, "pwdHistoryLength"),
        max_password_age_days=ticks_to_days(_attr_int(attrs, "maxPwdAge")),
        min_password_age_days=ticks_to_days(_attr_int(attrs, "minPwdAge")),
        password_properties_raw=properties,
        complexity_enabled=complexity_from_properties(properties),
        reversible_encryption=reversible_from_properties(properties),
        lockout_threshold=_attr_int(attrs, "lockoutThreshold"),
        lockout_duration_minutes=ticks_to_minutes(_attr_int(attrs, "lockoutDuration")),
        lockout_observation_window_minutes=ticks_to_minutes(_attr_int(attrs, "lockOutObservationWindow")),
        force_logoff_seconds=_ticks_to_seconds(force_logoff),
    )


_PSO_ATTRS = [
    "cn",
    "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordHistoryLength",
    "msDS-MaximumPasswordAge",
    "msDS-MinimumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-LockoutObservationWindow",
    "msDS-PasswordComplexityEnabled",
    "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PSOAppliesTo",
]


def _pso_from_attrs(attrs: dict[str, list[bytes]], name: str) -> PsoPolicy:
    """Build a PsoPolicy from a dereferenced msDS-PasswordSettings object's attributes.

    PSOs express complexity and reversible encryption as first-class booleans (not the packed
    PasswordProperties bits) and carry their own precedence and applies-to principals.
    """
    applies = [dn.decode("utf-8") for dn in attrs.get("msds-psoappliesto", [])]
    return PsoPolicy(
        name=name,
        precedence=_attr_int(attrs, "msDS-PasswordSettingsPrecedence"),
        min_password_length=_attr_int(attrs, "msDS-MinimumPasswordLength"),
        password_history_length=_attr_int(attrs, "msDS-PasswordHistoryLength"),
        max_password_age_days=ticks_to_days(_attr_int(attrs, "msDS-MaximumPasswordAge")),
        min_password_age_days=ticks_to_days(_attr_int(attrs, "msDS-MinimumPasswordAge")),
        lockout_threshold=_attr_int(attrs, "msDS-LockoutThreshold"),
        lockout_duration_minutes=ticks_to_minutes(_attr_int(attrs, "msDS-LockoutDuration")),
        lockout_observation_window_minutes=ticks_to_minutes(_attr_int(attrs, "msDS-LockoutObservationWindow")),
        complexity_enabled=_attr_bool(attrs, "msDS-PasswordComplexityEnabled"),
        reversible_encryption=_attr_bool(attrs, "msDS-PasswordReversibleEncryptionEnabled"),
        applies_to=applies,
    )


def ldap_password_settings_objects(target: Target, identity: BindIdentity, *, use_ldaps: bool) -> list[PsoPolicy]:
    """Enumerate every fine-grained password policy in the Password Settings Container ([MS-ADTS] 6.1.1.4.11.1).

    The container is admin-readable by default, so a non-privileged bind typically returns the objects'
    names but not their values; that denial is surfaced by the caller as the method being reachable but
    value-blind, which is itself a useful finding.
    """
    connection = _ldap_connect(target, identity, use_ldaps=use_ldaps)
    base = f"{PASSWORD_SETTINGS_CONTAINER_RDN},{_base_dn(identity.domain)}"
    try:
        entries = _search(connection, base, "wholeSubtree", "(objectClass=msDS-PasswordSettings)", _PSO_ATTRS)
    except LDAPSearchError as exc:
        msg = f"PSO container search failed: {exc}"
        raise OperationFailed(msg) from exc
    psos: list[PsoPolicy] = []
    for entry in entries:
        attrs = _entry_attrs(entry)
        name = _attr_str(attrs, "cn") or entry["objectName"].asOctets().decode("utf-8")
        pso = _pso_from_attrs(attrs, name)
        # A value-blind read (ACL hid the settings) shows only the name; flag it so the operator knows.
        blind = pso.min_password_length is None and pso.precedence is None
        psos.append(pso if not blind else PsoPolicy(name=name, applies_to=pso.applies_to, read_status="denied"))
    return psos


def ldap_resultant_pso(target: Target, identity: BindIdentity, user: str, *, use_ldaps: bool) -> tuple[str | None, PsoPolicy | None]:
    """Read msDS-ResultantPSO for a user (the winning PSO DN) and dereference it when readable.

    msDS-ResultantPSO is a constructed attribute the DC computes, so it directly names the PSO that governs
    the user; passwolf then dereferences that DN for its values (subject to the PSC ACL).
    """
    connection = _ldap_connect(target, identity, use_ldaps=use_ldaps)
    user_entries = _search(connection, _base_dn(identity.domain), "wholeSubtree", f"(sAMAccountName={user})", ["msDS-ResultantPSO"])
    if not user_entries:
        msg = f"could not find {user} to read msDS-ResultantPSO"
        raise OperationFailed(msg)
    pso_dn = _attr_str(_entry_attrs(user_entries[0]), "msDS-ResultantPSO")
    if pso_dn is None:
        return None, None  # the default domain policy governs this user (no PSO wins)
    pso_entries = _search(connection, pso_dn, "baseObject", "(objectClass=*)", _PSO_ATTRS)
    if not pso_entries:
        return pso_dn, None
    attrs = _entry_attrs(pso_entries[0])
    return pso_dn, _pso_from_attrs(attrs, _attr_str(attrs, "cn") or pso_dn)


def ldap_user_account_computed(target: Target, identity: BindIdentity, user: str, *, use_ldaps: bool) -> tuple[bool | None, bool | None, int | None]:
    """Read the computed lockout/expiry state for a user via msDS-User-Account-Control-Computed.

    The constructed msDS-User-Account-Control-Computed carries the live UF_LOCKOUT and UF_PASSWORD_EXPIRED
    bits ([MS-ADTS] 3.1.1.4.5.17, bit values per 2.2.16) that the static userAccountControl does not, giving the user's current standing
    against the policy alongside badPwdCount.
    """
    connection = _ldap_connect(target, identity, use_ldaps=use_ldaps)
    entries = _search(connection, _base_dn(identity.domain), "wholeSubtree", f"(sAMAccountName={user})", ["msDS-User-Account-Control-Computed", "badPwdCount"])
    if not entries:
        msg = f"could not find {user} to read computed account control"
        raise OperationFailed(msg)
    attrs = _entry_attrs(entries[0])
    computed = _attr_int(attrs, "msDS-User-Account-Control-Computed")
    locked = None if computed is None else bool(computed & UF_LOCKOUT)
    expired = None if computed is None else bool(computed & UF_PASSWORD_EXPIRED)
    return locked, expired, _attr_int(attrs, "badPwdCount")


# --- SYSVOL GptTmpl.inf configured intent (multi-GPO) ([MS-GPSB] 2.2.1; password keys 2.2.1.1, lockout keys 2.2.1.2) ---
def _sysvol_connect(target: Target, identity: BindIdentity) -> SMBConnection:
    """Open an authenticated SMB session to the DC for reading the SYSVOL policy templates."""
    connection = SMBConnection(target.dc, target.dc)
    if identity.use_kerberos:
        connection.kerberosLogin(**kerberos_login_args(identity, target.dc))
        return connection
    nt_hex = identity.nt_hash.hex() if identity.nt_hash is not None else ""
    lm_hex, nt_part = ("", "")
    if nt_hex:
        lm_hex, nt_part = "0" * 32, nt_hex
    connection.login(identity.user, identity.password, identity.domain, lm_hex, nt_part)
    return connection


def _list_policy_guids(connection: SMBConnection, domain: str) -> list[str]:
    r"""List the GPO GUID directories under SYSVOL\<domain>\Policies."""
    guids: list[str] = []
    for item in connection.listPath("SYSVOL", rf"{domain}\Policies\*"):
        name = item.get_longname()
        if item.is_directory() and name.startswith("{") and name.endswith("}"):
            guids.append(name)
    return guids


def _read_gpttmpl(connection: SMBConnection, domain: str, guid: str) -> bytes | None:
    """Fetch one GPO's GptTmpl.inf over SMB, returning None when that GPO defines no security template."""
    path = rf"{domain}\Policies\{guid}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    buffer = io.BytesIO()
    try:
        connection.getFile("SYSVOL", path, buffer.write)
    except SessionError:  # a GPO without a security template simply has no GptTmpl.inf
        return None
    return buffer.getvalue()


def _ini_int(parser: configparser.ConfigParser, key: str) -> int | None:
    """Read one [System Access] integer key (the INF stores them as plain decimals)."""
    raw = parser.get("System Access", key, fallback=None)
    if raw is None:
        return None
    try:
        return int(raw.strip().strip('"'))
    except ValueError:
        return None


def _ini_days(parser: configparser.ConfigParser, key: str) -> float | None:
    """Read a [System Access] age in days, mapping the INF -1 sentinel to inf (never)."""
    value = _ini_int(parser, key)
    if value is None:
        return None
    return float("inf") if value < 0 else float(value)


def _ini_minutes(parser: configparser.ConfigParser, key: str) -> float | None:
    """Read a [System Access] lockout window in minutes, mapping the INF -1 sentinel to inf (never)."""
    value = _ini_int(parser, key)
    if value is None:
        return None
    return float("inf") if value < 0 else float(value)


def _parse_gpttmpl(raw: bytes, guid: str, name: str) -> GptTmplPolicy | None:
    """Parse one GptTmpl.inf [System Access] block into a GptTmplPolicy, or None when it sets no policy.

    The template is UTF-16 with a BOM; only GPOs that actually set a [System Access] password key are
    returned, so the result lists exactly the GPOs that contribute to the configured password policy.
    """
    for encoding in ("utf-16", "utf-8-sig", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    # configparser lowercases option names on both store and lookup, so the mixed-case INF keys are
    # matched case-insensitively without overriding optionxform.
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    if not parser.has_section("System Access"):
        return None
    password_keys = ("MinimumPasswordLength", "PasswordComplexity", "PasswordHistorySize", "MaximumPasswordAge", "MinimumPasswordAge", "ClearTextPassword", "LockoutBadCount")
    if not any(parser.has_option("System Access", key) for key in password_keys):
        return None
    complexity = _ini_int(parser, "PasswordComplexity")
    reversible = _ini_int(parser, "ClearTextPassword")
    return GptTmplPolicy(
        gpo_name=name,
        gpo_guid=guid,
        min_password_length=_ini_int(parser, "MinimumPasswordLength"),
        password_history_size=_ini_int(parser, "PasswordHistorySize"),
        max_password_age_days=_ini_days(parser, "MaximumPasswordAge"),
        min_password_age_days=_ini_days(parser, "MinimumPasswordAge"),
        complexity_enabled=None if complexity is None else bool(complexity),
        reversible_encryption=None if reversible is None else bool(reversible),
        lockout_threshold=_ini_int(parser, "LockoutBadCount"),
        lockout_duration_minutes=_ini_minutes(parser, "LockoutDuration"),
        reset_lockout_minutes=_ini_minutes(parser, "ResetLockoutCount"),
    )


def sysvol_gpttmpl_policies(target: Target, identity: BindIdentity) -> list[GptTmplPolicy]:
    """Read every SYSVOL GPO security template and return those that configure password or lockout policy.

    This is the configured intent (what an admin set in Group Policy) rather than the live effective values,
    so it cross-checks the SAMR/LDAP reads and exposes drift or a not-yet-applied change.
    """
    connection = _sysvol_connect(target, identity)
    policies: list[GptTmplPolicy] = []
    for guid in _list_policy_guids(connection, identity.domain):
        raw = _read_gpttmpl(connection, identity.domain, guid)
        if raw is None:
            continue
        parsed = _parse_gpttmpl(raw, guid, guid)
        if parsed is not None:
            policies.append(parsed)
    return policies
