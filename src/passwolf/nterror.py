# SPDX-License-Identifier: Apache-2.0
"""NTSTATUS interpretation for password operations.

Both change and reset surface their outcome as an NTSTATUS in the RPC response. impacket collapses
several distinct codes into generic strings; passwolf decodes them precisely so the operator can tell
a wrong old password from a policy rejection from a method that the DC has disabled.
"""

from __future__ import annotations

from typing import Final

STATUS_SUCCESS: Final = 0x00000000
STATUS_UNSUCCESSFUL: Final = 0xC0000001  # generic failure stand-in for non-NTSTATUS protocols
STATUS_WRONG_PASSWORD: Final = 0xC000006A
STATUS_PASSWORD_RESTRICTION: Final = 0xC000006C  # [MS-ERREF]: singular, value 0xC000006C
STATUS_ACCESS_DENIED: Final = 0xC0000022
STATUS_NOT_SUPPORTED: Final = 0xC00000BB
STATUS_INVALID_PARAMETER: Final = 0xC000000D
STATUS_NO_SUCH_USER: Final = 0xC0000064
# SamrChangePasswordUser (opnum 38) cross-encryption retry signals: the server has authenticated the
# caller on one OWF but needs the new other-OWF cross-encrypted before it can store both ([MS-SAMR]
# 3.1.5.10.1; leaked Server 2003 ds/ds/src/sam/server/user.c:8892 and :9003).
STATUS_NT_CROSS_ENCRYPTION_REQUIRED: Final = 0xC000015D
STATUS_LM_CROSS_ENCRYPTION_REQUIRED: Final = 0xC000017F
# Returned by the authenticated bind when the account password is expired or flagged "must change at next
# logon"; the buffer-based SAMR changes can still proceed over a null session ([MS-SAMR] 3.1.5.10.3).
STATUS_PASSWORD_EXPIRED: Final = 0xC0000071
STATUS_PASSWORD_MUST_CHANGE: Final = 0xC0000224

# Each entry pairs the symbolic name with an operator-facing meaning. The meanings call out the
# behaviours that matter for routing: STATUS_ACCESS_DENIED from a legacy SAMR change on Server 2025 is
# the "RC4 change disabled" signal, not a per-user permission problem.
_NAMES: Final[dict[int, tuple[str, str]]] = {
    STATUS_SUCCESS: ("STATUS_SUCCESS", "operation succeeded"),
    STATUS_UNSUCCESSFUL: ("STATUS_UNSUCCESSFUL", "the operation failed (see the protocol detail)"),
    STATUS_WRONG_PASSWORD: ("STATUS_WRONG_PASSWORD", "the supplied old password is incorrect"),
    0xC000006B: ("STATUS_ILL_FORMED_PASSWORD", "the new password is malformed"),
    STATUS_PASSWORD_RESTRICTION: ("STATUS_PASSWORD_RESTRICTION", "new password rejected by policy (length, complexity, history, or minimum age)"),
    STATUS_INVALID_PARAMETER: ("STATUS_INVALID_PARAMETER", "the server rejected the request structure"),
    STATUS_ACCESS_DENIED: ("STATUS_ACCESS_DENIED", "access denied (insufficient rights, or this method is disabled on the DC)"),
    STATUS_NOT_SUPPORTED: ("STATUS_NOT_SUPPORTED", "this method is not supported on the DC"),
    STATUS_PASSWORD_EXPIRED: ("STATUS_PASSWORD_EXPIRED", "the account password is expired"),
    STATUS_PASSWORD_MUST_CHANGE: ("STATUS_PASSWORD_MUST_CHANGE", "the account password must be changed before the next logon"),
    0xC0000072: ("STATUS_ACCOUNT_DISABLED", "the account is disabled"),
    0xC0000193: ("STATUS_ACCOUNT_EXPIRED", "the account is expired"),
    0xC0000234: ("STATUS_ACCOUNT_LOCKED_OUT", "the account is locked out"),
    STATUS_NO_SUCH_USER: ("STATUS_NO_SUCH_USER", "no such user (or wrong account type for this method)"),
    STATUS_NT_CROSS_ENCRYPTION_REQUIRED: ("STATUS_NT_CROSS_ENCRYPTION_REQUIRED", "the server needs the new NT hash cross-encrypted with the new LM hash (opnum 38 retry)"),
    STATUS_LM_CROSS_ENCRYPTION_REQUIRED: ("STATUS_LM_CROSS_ENCRYPTION_REQUIRED", "the server needs the new LM hash cross-encrypted with the new NT hash (opnum 38 retry)"),
    0xC000018C: ("STATUS_TRUSTED_DOMAIN_FAILURE", "the trust relationship failed"),
}


def name(status: int) -> str:
    """Return the symbolic NTSTATUS name, or a hex fallback for an unmapped code."""
    code = status & 0xFFFFFFFF
    entry = _NAMES.get(code)
    return entry[0] if entry else f"0x{code:08X}"


def describe(status: int) -> str:
    """Return a one-line operator-facing description of an NTSTATUS code."""
    code = status & 0xFFFFFFFF
    entry = _NAMES.get(code)
    if entry:
        return f"{entry[0]} (0x{code:08X}): {entry[1]}"
    return f"unmapped NTSTATUS 0x{code:08X}"


def is_success(status: int) -> bool:
    """Return whether an NTSTATUS code indicates success."""
    return (status & 0xFFFFFFFF) == STATUS_SUCCESS
