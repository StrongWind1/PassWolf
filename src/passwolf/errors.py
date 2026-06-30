"""Exception types used to drive method selection and report failures."""

from __future__ import annotations


class PasswolfError(Exception):
    """Base class for passwolf operational errors."""


class MethodUnavailable(PasswolfError):
    """Raised when a method is not implemented or not reachable on this DC, so AUTO can fall back.

    This is distinct from an NTSTATUS result: it means the RPC opnum faulted out of range, the
    transport cannot carry the method, or a required input is missing, not that the server evaluated
    the request and rejected it.
    """


class OperationFailed(PasswolfError):
    """Raised when a non-NTSTATUS protocol (Kerberos kpasswd or LDAP) reports a definite failure.

    These protocols return their own result codes rather than an NTSTATUS, so the carried message is
    the authoritative detail for the operator.
    """
