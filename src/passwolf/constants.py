# SPDX-License-Identifier: Apache-2.0
"""Spec-derived constants shared across the password methods.

Every value here is traceable to a Microsoft Open Specification section. Grouping them in one
module keeps the per-method code free of magic numbers and makes the spec mapping auditable.
"""

from __future__ import annotations

from typing import Final

# --- [MS-SAMR] 2.2.1.18 AEAD-AES-256-CBC-HMAC-SHA512 constants ---
# The two key-derivation labels are NUL-terminated ANSI strings; the trailing 0x00 is part of the
# HMAC input, so the byte lengths (61 and 54) include the terminator.
SAM_AES256_ENC_KEY_STRING: Final = b"Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"
SAM_AES256_MAC_KEY_STRING: Final = b"Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"

# --- [MS-LSAD] 2.2.1.4 AEAD-AES-256-CBC-HMAC-SHA512 constants (trust-secret store) ---
LSAD_AES256_ENC_KEY_STRING: Final = b"Microsoft LSAD encryption key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"
LSAD_AES256_MAC_KEY_STRING: Final = b"Microsoft LSAD MAC key AEAD-AES-256-CBC-HMAC-SHA512 16\x00"

# AEAD framing byte used in both the SAM and LSAD constructions.
AEAD_VERSION_BYTE: Final = 0x01

# --- Password buffer geometry ([MS-SAMR] 2.2.6.x) ---
SAM_MAX_PASSWORD_WCHARS: Final = 256  # SAMPR_USER_PASSWORD(_AES) Buffer is 256 WCHARs == 512 bytes
PASSWORD_BUFFER_BYTES: Final = SAM_MAX_PASSWORD_WCHARS * 2  # 512
NL_TRUST_PASSWORD_BUFFER_BYTES: Final = 512  # [MS-NRPC] 2.2.1.3.7 NL_TRUST_PASSWORD.Buffer

# --- [MS-SAMR] 3.2.2.5 PBKDF2 iteration bounds for the AES change CEK ---
PBKDF2_ITERATIONS_MIN: Final = 5000
PBKDF2_ITERATIONS_MAX: Final = 1_000_000
PBKDF2_ITERATIONS_DEFAULT: Final = 10_000

# --- [MS-SAMR] 2.2.6.x USER_INFORMATION_CLASS levels used by SamrSetInformationUser2 ---
USER_INTERNAL1_INFORMATION: Final = 18  # NT/LM OWF set-hash (DES over session key)
USER_ALL_INFORMATION: Final = 21  # NT/LM OWF set-hash via the all-information block (WhichFields-gated)
USER_INTERNAL4_INFORMATION: Final = 23  # cleartext, RC4 over session key
USER_INTERNAL5_INFORMATION: Final = 24  # cleartext, RC4 over session key
USER_INTERNAL4_INFORMATION_NEW: Final = 25  # cleartext, RC4 keyed by MD5(salt + session key)
USER_INTERNAL5_INFORMATION_NEW: Final = 26  # cleartext, RC4 keyed by MD5(salt + session key)
USER_INTERNAL7_INFORMATION: Final = 31  # cleartext, AEAD-AES (CEK = session key)
USER_INTERNAL8_INFORMATION: Final = 32  # cleartext, AEAD-AES wrapping UserAllInformation

# --- USER_INFORMATION_CLASS levels that are NOT settable by a remote caller ---
# These three levels exist in the leaked 2003 enum but cannot be written through SamrSetInformationUser
# or SamrSetInformationUser2 (opnum 37 / 58) from any over-the-wire client, and they are absent from the
# modern public [MS-SAMR] enum and SAMPR_USER_INFO_BUFFER union (v20260427: the enum jumps 18 -> 20 and
# 21 -> 23). Every SamrConnect* dispatch hard-codes the context as untrusted (server.c SamrConnect/2/3:
# "all remote clients are considered untrusted", TrustedClient = FALSE); the only TrustedClient = TRUE
# path is the in-process SamI* API inside lsass (for example SamISetPasswordForeignUser, user.c:11974),
# which is not an RPC opnum. A remote SET of any of these returns STATUS_INVALID_INFO_CLASS. Verified
# live on Server 2003, XP SP3, Server 2022, and Server 2025 across both opnums and every buffer shape.
USER_INTERNAL2_INFORMATION: Final = 19  # NOT settable: logon statistics, trusted/in-process only (user.c:7489/7786)
USER_INTERNAL3_INFORMATION: Final = 22  # NOT settable: a query-only result (UserAll + LastBadPasswordTime); no SET union arm
USER_INTERNAL6_INFORMATION: Final = 27  # NOT settable: internal query-only class; never in the SET union

# --- [MS-SAMR] 2.2.6.6 SAMPR_USER_ALL_INFORMATION WhichFields bits ---
# Used by the UserInternal8 reset; the server's own UserInternal7 -> UserInternal8 mapping
# ([MS-SAMR] 3.1.5.6.4.1) sets exactly these two bits.
USER_ALL_NTPASSWORDPRESENT: Final = 0x0100_0000
USER_ALL_LMPASSWORDPRESENT: Final = 0x0200_0000
USER_ALL_PASSWORDEXPIRED: Final = 0x0800_0000

# --- Well-known RIDs ---
DOMAIN_USER_RID_ADMIN: Final = 0x1F4  # 500, the only account SamrSetDSRMPassword (opnum 66) addresses

# --- [MS-NRPC] negotiate flags requesting AES secure-channel cryptography ---
# Bit W (0x01000000) selects AES-128-CFB8 / HMAC-SHA256 for the secure channel.
NETLOGON_FLAGS_AES: Final = 0x612FFFFF

# --- [MS-SAMR] 2.2.7.15 SAMPR_REVISION_INFO_V1 SupportedFeatures (from SamrConnect5) ---
# Bit 0x10, when set, tells the client to use AES (the SAMPR_ENCRYPTED_PASSWORD_AES buffer) for password
# writes; this drives the deterministic AES-vs-RC4 preflight per [MS-SAMR] 3.2.2.4.
SAMP_SUPPORTED_FEATURE_AES: Final = 0x0000_0010

# --- SAMR opnums, annotated with their spec sections ---
# The SamrSetInformationUser/User2 (37/58) and SamrUnicodeChangePasswordUser3/4 (63/73) values drive
# opnum/method selection in reset.py, samr.py, and ndr.py; the rest map the interface for reference.
OPNUM_SAMR_CONNECT5: Final = 64  # SamrConnect5, carries the SupportedFeatures preflight
OPNUM_SAMR_QUERY_INFORMATION_DOMAIN: Final = 8  # SamrQueryInformationDomain ([MS-SAMR] 3.1.5.5.2)
OPNUM_SAMR_CHANGE_PASSWORD_USER: Final = 38
OPNUM_SAMR_GET_USER_DOMAIN_PASSWORD_INFORMATION: Final = 44  # per-user, PSO-aware ([MS-SAMR] 3.1.5.13.1)
OPNUM_SAMR_QUERY_INFORMATION_DOMAIN2: Final = 46  # SamrQueryInformationDomain2 ([MS-SAMR] 3.1.5.5.1)
OPNUM_SAMR_OEM_CHANGE_PASSWORD_USER2: Final = 54
OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER2: Final = 55
OPNUM_SAMR_GET_DOMAIN_PASSWORD_INFORMATION: Final = 56  # handle-light ([MS-SAMR] 3.1.5.13.2)
OPNUM_SAMR_SET_INFORMATION_USER: Final = 37  # SamrSetInformationUser, the deprecated equal of opnum 58
OPNUM_SAMR_SET_INFORMATION_USER2: Final = 58
OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER3: Final = 63
OPNUM_SAMR_SET_DSRM_PASSWORD: Final = 66
OPNUM_SAMR_UNICODE_CHANGE_PASSWORD_USER4: Final = 73

# --- [MS-SAMR] 2.2.3.9 DOMAIN_INFORMATION_CLASS levels carrying password / lockout policy ---
DOMAIN_PASSWORD_INFORMATION: Final = 1  # min length, history, ages, PasswordProperties
DOMAIN_GENERAL_INFORMATION: Final = 2  # adds force-logoff and the domain head fields
DOMAIN_LOGOFF_INFORMATION: Final = 3  # ForceLogoff delta-time
DOMAIN_GENERAL_INFORMATION2: Final = 11  # DOMAIN_GENERAL_INFORMATION plus LockoutDuration/Window/Threshold
DOMAIN_LOCKOUT_INFORMATION: Final = 12  # LockoutDuration, LockoutObservationWindow, LockoutThreshold

# --- [MS-SAMR] 2.2.1.7 user-object specific access mask bits used by the per-user reads ---
USER_READ_GENERAL: Final = 0x0000_0001  # required by SamrGetUserDomainPasswordInformation (opnum 44)
USER_READ_ACCOUNT: Final = 0x0000_0008

# --- [MS-SAMR] 2.2.1.5 domain-object access bits gating the policy reads ---
DOMAIN_READ_PASSWORD_PARAMETERS: Final = 0x0000_0001  # class 1
DOMAIN_READ_OTHER_PARAMETERS: Final = 0x0000_0004  # classes 2/11/12

# --- [MS-ADTS] 3.1.1.4.5.17 msDS-User-Account-Control-Computed bits (values per 2.2.16) ---
UF_LOCKOUT: Final = 0x0000_0010
UF_PASSWORD_EXPIRED: Final = 0x0080_0000

# --- Active Directory well-known container RDNs for fine-grained password policy ([MS-ADTS] 6.1.1.4.11.1) ---
PASSWORD_SETTINGS_CONTAINER_RDN: Final = "CN=Password Settings Container,CN=System"
DEFAULT_DOMAIN_POLICY_GUID: Final = "{31B2F340-016D-11D2-945F-00C04FB984F9}"  # the seeded Default Domain Policy GPO

# --- Netlogon opnums ---
OPNUM_NRPC_SERVER_PASSWORD_SET: Final = 6
OPNUM_NRPC_SERVER_PASSWORD_SET2: Final = 30

# --- LSAD opnums ---
OPNUM_LSAD_SET_SECRET: Final = 29
OPNUM_LSAD_SET_SECRET2: Final = 138
