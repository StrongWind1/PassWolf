# What it looks like in the logs

Every passwolf method was run against live domain controllers (Windows Server 2022 build 20348 and Server 2025 build 26100) with full auditing enabled, and the Windows Security log was read back after each run to record which events fired. This page maps each method to the events a defender will see on the target account, and notes which methods are quiet.

## The events involved

Six Security event IDs cover everything on this page.

| Event ID | Name | Meaning |
|---|---|---|
| 4723 | An attempt was made to change an account's password | A password was changed (the caller proved the old password). |
| 4724 | An attempt was made to reset an account's password | A password was reset (privileged; no old password required). |
| 4738 | A user account was changed | A general account-modified event that often accompanies a change or reset. |
| 4742 | A computer account was changed | The machine-account equivalent of 4738. |
| 4768 | A Kerberos authentication ticket (TGT) was requested | A Kerberos logon occurred; this is the marker of the kpasswd method. |
| 4794 | An attempt was made to set the DSRM administrator password | The Directory Services Restore Mode recovery password was set. |

Two further events appear as background on the SAMR and NTLM-bound methods: 4776 (the DC validated NTLM credentials for the connecting account) and 4624 / 4634 (the connecting account logged on and off). These belong to the connection, not the password operation, so they name the caller rather than the account whose password changed.

## Method to event map

The "Primary events" column lists only the events tied to the target account. Results were identical on Server 2022 and Server 2025 except where the last column states otherwise.

| passwolf method | Operation | Primary events on the target | Notes |
|---|---|---|---|
| `passwolf reset`: `samr-aes`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash` | reset | **4724** | Every SAMR reset produces the same event. The cipher and the info level do not change it, so AES and a raw-hash set are indistinguishable at the event layer. |
| `passwolf reset`: `kpasswd`, `ldap` | reset | **4724** + 4738 | A reset, plus the general account-modified event. |
| `passwolf reset --reset-info-class <class>` (any of the eight classes, opnum 37 or 58) | reset | **4724** | The advanced wire forms all emit the same single reset event. |
| `passwolf reset --dsrm` | reset (recovery account) | **4794** (+ 4674) | The only operation with a dedicated event. 4794 has no other source. |
| `passwolf change`: `samr-aes`, `samr-rc4`, `samr-des`, `samr-diag` | change | **4723** + 4738 | A password change. The account proved its old secret. |
| `passwolf change`: `kpasswd` | change | **4768** + **4723** + 4738 | The only change preceded by a Kerberos ticket request (4768). |
| `passwolf change`: `ldap` | change | **4723** + 4738 | A change carried as an attribute write over an encrypted LDAP channel. |
| `passwolf change --account machine`: `netlogon-aes` | change (computer) | **4742** only | A single computer-account-changed event, with no 4723 and no 4724. |
| `passwolf change --account machine`: `netlogon-des` | change (computer) | **4742** + **4724** | As above, but the DES variant also logs a reset event. |
| `passwolf change`: `samr-aes` against a computer account | change (computer) | **4742** + **4723** | Changing a computer's password over SAMR records an ordinary change. |
| `passwolf policy`, any read (`samr-*`, `kpasswd`, `ldap-*`, `sysvol`) | read | **none** | Reading the password policy produces no event tied to the account. |

## What changes on Server 2025

Server 2025 hardens off the legacy RC4 SAMR password changes (CVE-2021-33757 / KB5004605), which affects detection in two ways.

- The legacy SAMR changes (`samr-rc4`, `samr-oem`, `samr-des`, `samr-diag`) are rejected with `STATUS_ACCESS_DENIED` before the change is processed, so no 4723 is written. A blocked attempt leaves only the NTLM and logon events of the connection (4776, 4624), with no password event. Only `samr-aes`, `kpasswd`, and `ldap` changes succeed and log 4723.
- Resets are not affected. Every reset still logs 4724 on Server 2025, as on 2022. The 2025 hardening applies to changes, not resets.

## Detection notes

- 4724 marks a reset and 4723 marks a change, but neither identifies the cipher or wire form. All SAMR resets collapse to one 4724 and all SAMR changes collapse to one 4723.
- A 4768 immediately before a 4723 or 4724 indicates the Kerberos password protocol rather than a SAMR or LDAP path. It is the only method that produces a distinguishing event.
- 4794 has no source other than a DSRM password set, so it suits a dedicated alert.
- `netlogon-aes` writes a new computer-account password and logs only 4742, with no 4723 or 4724. A rule scoped to password-change and reset events alone will not catch it.
- `passwolf policy` leaves no per-account trace, so policy enumeration does not appear where password operations are logged.
- On Server 2025 a blocked legacy change is rejected before the audit point, so the only evidence is the connection's NTLM and logon events, not a failed-change event.

## Enabling these events

These events appear only with the relevant auditing enabled. The captures above used the Advanced Audit Policy with, at minimum: Account Management (User Account Management and Computer Account Management, covering 4720 through 4794), Account Logon (Kerberos Authentication Service for 4768, Credential Validation for 4776), DS Access, and Detailed Tracking (RPC Events). On a default-audited domain controller the account-management events (4723, 4724, 4738, 4742, 4794) are generally present, while the Kerberos, NTLM, and RPC detail require the subcategories to be turned on.
