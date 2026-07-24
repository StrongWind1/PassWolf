# SPDX-License-Identifier: Apache-2.0
"""Normalized records and decoders for the password-policy read tool (``passwolf policy``).

Every read method (the SAMR domain-query classes, the handle-light and per-user SAMR getters, the
opnum-63 change-failure oracle, the kpasswd SOFTERROR blob, the LDAP domain head and PSO objects, and
the SYSVOL ``GptTmpl.inf``) fills the same canonical vocabulary so disparate sources can be reported
side by side. The wire formats differ: SAMR and LDAP carry signed 64-bit 100-nanosecond delta-time
intervals (``OLD_LARGE_INTEGER`` / ``Interval``), kpasswd reports ages already converted to days, and
SYSVOL stores ages in days and lockout windows in minutes. Everything is normalized here to days for
ages and minutes for the lockout windows. This module is kept apart from ``model.py`` so the read
vocabulary never mixes with the change/reset model, while still importing nothing from it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- DOMAIN_PASSWORD_* property bits (PasswordProperties, [MS-SAMR] 2.2.3.1) ---
# The same bitmask is carried by SAMR PasswordProperties, the LDAP pwdProperties attribute, and the
# kpasswd SOFTERROR flags field, so one decoder serves all three. The names are the spec's exact constant
# names; note 0x08 is DOMAIN_LOCKOUT_ADMINS (not DOMAIN_PASSWORD_LOCKOUT_ADMINS) per the spec table.
PASSWORD_PROPERTY_FLAGS: dict[int, str] = {
    0x01: "DOMAIN_PASSWORD_COMPLEX",
    0x02: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
    0x04: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
    0x08: "DOMAIN_LOCKOUT_ADMINS",
    0x10: "DOMAIN_PASSWORD_STORE_CLEARTEXT",
    0x20: "DOMAIN_REFUSE_PASSWORD_CHANGE",
}
PASSWORD_COMPLEX_BIT = 0x01  # complexity enforced
PASSWORD_STORE_CLEARTEXT_BIT = 0x10  # reversible encryption enabled

# A delta-time Interval of int64-min (0x8000000000000000) is the "never" / infinite sentinel; AD also
# uses 0 for "not set". Ages are stored as a negative number of 100-nanosecond ticks.
_TICKS_PER_SECOND = 10_000_000
_NEVER_MAGNITUDE = 0x7FFFFFFFFFFFFFFF  # magnitudes at or above this mean "never"


def ticks_to_days(ticks: int | None) -> float | None:
    """Convert a signed 100ns delta-time interval to whole days, or ``inf`` for the never sentinel.

    Returns ``None`` when the field was not read, ``inf`` for the int64-min "never" value, and the
    positive magnitude in days otherwise (the wire value is negative for an elapsed duration).
    """
    if ticks is None:
        return None
    magnitude = abs(int(ticks))
    if magnitude >= _NEVER_MAGNITUDE:
        return float("inf")
    return round(magnitude / (_TICKS_PER_SECOND * 86400), 4)


def ticks_to_minutes(ticks: int | None) -> float | None:
    """Convert a signed 100ns delta-time interval to minutes, or ``inf`` for the never sentinel."""
    if ticks is None:
        return None
    magnitude = abs(int(ticks))
    if magnitude >= _NEVER_MAGNITUDE:
        return float("inf")
    return round(magnitude / (_TICKS_PER_SECOND * 60), 4)


def decode_properties(properties: int | None) -> list[str]:
    """Decode a PasswordProperties / pwdProperties bitmask into its set flag names."""
    if properties is None:
        return []
    return [name for bit, name in PASSWORD_PROPERTY_FLAGS.items() if properties & bit]


def complexity_from_properties(properties: int | None) -> bool | None:
    """Read the complexity bit out of a packed properties mask (``None`` when the mask is absent)."""
    return None if properties is None else bool(properties & PASSWORD_COMPLEX_BIT)


def reversible_from_properties(properties: int | None) -> bool | None:
    """Read the store-cleartext (reversible encryption) bit out of a packed properties mask."""
    return None if properties is None else bool(properties & PASSWORD_STORE_CLEARTEXT_BIT)


@dataclass(frozen=True)
class PasswordPolicy:
    """The normalized default-domain policy from one source.

    Every field is optional because no single method fills all of them: SAMR class 1 has no lockout,
    op56/op44 carry only length and properties, and the kpasswd blob has no lockout. Each source emits
    its own record (tagged by ``source``) so disagreements between methods are visible, not merged away.

    ``scope`` records whether the record is the domain-wide default policy (``"domain"``) or a per-user,
    PSO-resolved effective policy (``"PSO"``), so the renderer can tell the operator which one each row is.
    """

    source: str
    scope: str = "domain"  # "domain" (default-domain policy) | "PSO" (per-user, fine-grained effective)
    min_password_length: int | None = None
    password_history_length: int | None = None
    max_password_age_days: float | None = None
    min_password_age_days: float | None = None
    complexity_enabled: bool | None = None
    reversible_encryption: bool | None = None
    password_properties_raw: int | None = None
    lockout_threshold: int | None = None
    lockout_duration_minutes: float | None = None
    lockout_observation_window_minutes: float | None = None
    force_logoff_seconds: float | None = None

    @property
    def property_flags(self) -> list[str]:
        """The decoded names of the set PasswordProperties bits."""
        return decode_properties(self.password_properties_raw)


@dataclass(frozen=True)
class PsoPolicy:
    """One fine-grained password-settings object (PSO).

    PSOs are the only source where complexity and reversible encryption are first-class booleans rather
    than packed bits, and the only place precedence and the applies-to principals are expressed.
    """

    name: str
    precedence: int | None = None
    min_password_length: int | None = None
    password_history_length: int | None = None
    max_password_age_days: float | None = None
    min_password_age_days: float | None = None
    lockout_threshold: int | None = None
    lockout_duration_minutes: float | None = None
    lockout_observation_window_minutes: float | None = None
    complexity_enabled: bool | None = None
    reversible_encryption: bool | None = None
    applies_to: list[str] = field(default_factory=list)
    read_status: str = "ok"  # ok | denied (the PSC ACL hides values from non-admins)


@dataclass(frozen=True)
class GptTmplPolicy:
    """The [System Access] settings parsed from one GPO's SYSVOL GptTmpl.inf (configured intent).

    Ages here are in days and lockout windows in minutes (the units the INF file stores), already the
    canonical units, so they are reported as the configured-intent cross-check next to the live values.
    """

    gpo_name: str
    gpo_guid: str
    min_password_length: int | None = None
    password_history_size: int | None = None
    max_password_age_days: float | None = None
    min_password_age_days: float | None = None
    complexity_enabled: bool | None = None
    reversible_encryption: bool | None = None
    lockout_threshold: int | None = None
    lockout_duration_minutes: float | None = None
    reset_lockout_minutes: float | None = None


@dataclass(frozen=True)
class UserPolicyView:
    """The PSO-effective view of the ``--target-user`` account, assembled when a target user is supplied.

    This summarizes the fine-grained policy that governs the target: whether a PSO wins (``resultant_pso``)
    or the domain default governs, the winning PSO's values, the opnum-44 effective length/complexity, and
    the account's live standing (lockout / expiry / bad-password count). The op63 and kpasswd oracle records
    are kept out of this view because they report the *authenticating* principal's effective policy, not the
    target's; they live in ``PolicyReadResult.policies`` tagged ``scope="PSO"`` like any other policy record.
    """

    principal: str  # the target user (DOMAIN\\target-user)
    resultant_pso: str | None = None  # the winning PSO DN, or None when the default policy governs
    effective_pso: PsoPolicy | None = None  # the dereferenced winner's values
    op44_min_length: int | None = None  # SamrGetUserDomainPasswordInformation, PSO-resolved
    op44_complexity: bool | None = None
    op44_reversible: bool | None = None
    is_locked_out: bool | None = None  # msDS-User-Account-Control-Computed UF_LOCKOUT
    password_expired: bool | None = None  # msDS-User-Account-Control-Computed UF_PASSWORD_EXPIRED
    bad_password_count: int | None = None


@dataclass
class PolicyReadResult:
    """Everything a ``passwolf policy`` run gathered, plus a per-method reachability map.

    The reachability map is the point of an anonymous run: it shows exactly which method leaked the
    policy and which were denied, rather than collapsing to one answer.
    """

    target: str
    dc: str
    policies: list[PasswordPolicy] = field(default_factory=list)
    psos: list[PsoPolicy] = field(default_factory=list)
    gpo_policies: list[GptTmplPolicy] = field(default_factory=list)
    user_view: UserPolicyView | None = None
    reachability: dict[str, str] = field(default_factory=dict)  # method id -> ok|denied|unavailable|skipped: reason
