# SPDX-License-Identifier: Apache-2.0
"""Shared CLI data model: enums, target/secret records, and input parsing.

These types are transport- and protocol-agnostic so both ``passwolf change`` and ``passwolf reset`` build on the
same vocabulary. The change-versus-reset split is encoded in two separate method enums that never
overlap, mirroring the project rule that change and reset are distinct operations.
"""

from __future__ import annotations

import binascii
import getpass
from dataclasses import dataclass
from enum import StrEnum

NT_HASH_BYTES = 16


class OutputFormat(StrEnum):
    """How results are rendered to the terminal."""

    TEXT = "text"
    JSON = "json"
    PRETTY = "pretty"


class TransportKind(StrEnum):
    """Which DCE/RPC transport carries SAMR, Netlogon, or LSA."""

    SMB = "smb"  # ncacn_np over an SMB named pipe (TCP 445)
    TCP = "tcp"  # ncacn_ip_tcp, endpoint-mapper resolved


class AccountKind(StrEnum):
    """The kind of principal whose password is being changed."""

    USER = "user"  # a normal user or service account (SAMR / kpasswd / LDAP)
    MACHINE = "machine"  # a computer account, rotated over the Netlogon secure channel
    TRUST = "trust"  # an interdomain trust account, rotated over the Netlogon secure channel


class ChangeMethod(StrEnum):
    """A method that CHANGES a password by proving the account's current secret."""

    AUTO = "auto"  # pick the strongest method the DC accepts, then fall back
    SAMR_AES = "samr-aes"  # SamrUnicodeChangePasswordUser4, opnum 73 (AES)
    SAMR_RC4 = "samr-rc4"  # SamrUnicodeChangePasswordUser2, opnum 55 (RC4)
    SAMR_OEM = "samr-oem"  # SamrOemChangePasswordUser2, opnum 54 (RC4 keyed by old LM)
    SAMR_DES = "samr-des"  # SamrChangePasswordUser, opnum 38 (DES cross-encryption, needs a handle)
    SAMR_DIAG = "samr-diag"  # SamrUnicodeChangePasswordUser3, opnum 63 (undocumented, policy diagnostics)
    KPASSWD = "kpasswd"  # Kerberos change protocol, version 0x0001
    LDAP = "ldap"  # LDAP unicodePwd delete-old + add-new
    NETLOGON_AES = "netlogon-aes"  # NetrServerPasswordSet2, opnum 30 (machine/trust)
    NETLOGON_DES = "netlogon-des"  # NetrServerPasswordSet, opnum 6 (machine/trust)
    RAP = "rap"  # RAP NetUserPasswordSet2, opcode 115 over SMB1 \PIPE\LANMAN (legacy cleartext)
    RAP_OEM = "rap-oem"  # RAP SamOEMChangePasswordUser2, undocumented opcode 214 over SMB1 (legacy RC4 OEM)


class ResetMethod(StrEnum):
    """A method that RESETS a password by privileged overwrite, proving nothing about the old one."""

    AUTO = "auto"  # pick the strongest method the DC accepts, then fall back
    SAMR_AES = "samr-aes"  # SamrSetInformationUser2 + UserInternal7 (AES, cleartext, password-only)
    SAMR_RC4 = "samr-rc4"  # SamrSetInformationUser2 + UserInternal4InformationNew (RC4 + MD5 salt)
    SAMR_RC4_UNSALTED = "samr-rc4-unsalted"  # SamrSetInformationUser2 + UserInternal4Information (RC4, no salt)
    SAMR_HASH = "samr-hash"  # SamrSetInformationUser + UserInternal1 (set NT/LM OWF directly)
    KPASSWD = "kpasswd"  # Kerberos set protocol, version 0xFF80, with target name/realm
    LDAP = "ldap"  # LDAP unicodePwd single replace
    DSRM = "dsrm"  # SamrSetDSRMPassword, opnum 66 (the DC-local recovery account, selected with --dsrm)


@dataclass(frozen=True)
class Target:
    """A resolved target: the account to act on and the domain controller to reach."""

    domain: str
    user: str
    dc: str


@dataclass(frozen=True)
class Secret:
    """A password secret expressed as cleartext, an NT hash, or both unset.

    A change proves the OLD secret; a pass-the-hash change supplies only the NT hash. A reset writes a
    NEW secret, which for the set-hash path is an NT (and optionally LM) hash rather than cleartext.
    """

    password: str | None = None
    nt_hash: bytes | None = None
    lm_hash: bytes | None = None

    def require_password(self) -> str:
        """Return the cleartext password or raise when only a hash is available."""
        if self.password is None:
            msg = "this method requires a cleartext password, not a hash"
            raise ValueError(msg)
        return self.password


def prompt_password(label: str) -> str:
    """Read a password from the terminal without echoing it.

    Used as the interactive fallback when a ``--*-password`` flag is omitted, so the secret never has to
    appear on the command line where the process list would expose it to other local users.
    """
    return getpass.getpass(f"{label}: ")


def parse_hash_pair(value: str | None) -> tuple[bytes | None, bytes | None]:
    """Parse ``LM:NT`` or a bare ``NT`` hash string into raw (lm, nt) byte pairs.

    A single 32-hex value is treated as the NT hash with no LM half. Either half may be the well-known
    empty-string placeholder ``aad3b435b51404eeaad3b435b51404ee`` (LM) which is returned as-is.
    """
    if not value:
        return None, None
    parts = value.split(":")
    nt_hex = parts[-1].strip()
    lm_hex = parts[0].strip() if len(parts) > 1 else ""
    nt = _unhex_hash(nt_hex, "NT") if nt_hex else None
    lm = _unhex_hash(lm_hex, "LM") if lm_hex else None
    return lm, nt


def _unhex_hash(hex_value: str, label: str) -> bytes:
    """Decode a 32-character hex hash into 16 raw bytes, raising on a wrong length."""
    raw = binascii.unhexlify(hex_value)
    if len(raw) != NT_HASH_BYTES:
        msg = f"{label} hash must be 32 hex characters (16 bytes)"
        raise ValueError(msg)
    return raw
