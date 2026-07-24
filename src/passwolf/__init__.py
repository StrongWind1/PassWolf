# SPDX-License-Identifier: Apache-2.0
"""passwolf: correct, spec-compliant Active Directory password change, reset, and policy read.

One console command, ``passwolf``, with three subcommands — ``change``, ``reset``, and ``policy``
— that implement every documented and undocumented Windows method for changing or resetting an
account password or hash over SAMR, Netlogon, LSA, Kerberos kpasswd, and LDAP, and for reading the
effective password policy. The change and reset operations are kept strictly separate: a CHANGE
proves the account's current secret and needs no privilege, a RESET is a privileged overwrite that
proves nothing. The wire formats and cryptography are traced to
the Microsoft Open Specifications and validated against live domain controllers, including
the AES paths that impacket does not implement and that a Windows Server 2025 SAMR change requires.
"""

from __future__ import annotations

__version__ = "0.3.1"
