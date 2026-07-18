<h1 align="center">PassWolf</h1>

<p align="center"><strong>Active Directory password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, and LDAP.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/passwolf/"><img src="https://img.shields.io/pypi/v/passwolf.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind1.github.io/PassWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/PassWolf/guide/getting-started/">Getting started</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/guide/choosing-a-method/">Choosing a method</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/methods/">Method matrix</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/reference/samr/">CLI reference</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/">Documentation</a>
</p>

One console command, `passwolf`, with three subcommands - `passwolf change`, `passwolf reset`, and `passwolf policy` - that implement every documented and undocumented Windows method for changing or resetting an Active Directory account password over SAMR, Netlogon, LSA, Kerberos kpasswd, and LDAP, and for reading the effective password policy. 11 change methods, 6 reset methods, and full policy read across 5 protocols - including the AES SAMR paths that Windows Server 2025 requires and no other public tool implements.

**[Full documentation](https://strongwind1.github.io/PassWolf/)**

## Why PassWolf

The AD password-change landscape is fragmented across tools that each cover a few methods and skip the rest. PassWolf consolidates every documented (and undocumented) change and reset path into one tool, with the AES methods Server 2025 demands.

| Capability | PassWolf | impacket | bloodyAD | NetExec | rpcclient |
|---|:---:|:---:|:---:|:---:|:---:|
| AES SAMR change (Server 2025) | yes | no | no | no | no |
| RC4 / OEM / DES SAMR changes | 4 methods | 1 | no | 1 | 1 |
| Diagnostic change (structured rejection reason) | yes | no | no | no | no |
| Kerberos kpasswd change | yes | yes | no | no | no |
| Kerberos kpasswd set (privileged reset) | yes | no | no | no | no |
| LDAP change + reset (sealed 389, no cert needed) | both | both | reset only | no | no |
| SAMR reset (AES / RC4 / set-hash) | 3 methods | no | no | no | partial |
| Netlogon machine / trust password | AES + DES | no | no | no | no |
| DSRM reset (DC recovery account) | yes | no | no | no | no |
| RAP legacy change (SMB1) | 2 methods | no | no | no | no |
| Pass-the-hash change | yes | yes | no | yes | no |
| Expired / must-change password handling | yes | no | no | no | no |
| Password policy read (domain + PSO + GPO) | yes | no | partial | partial | partial |
| Auto method selection with fallback | yes | no | no | no | no |
| Server 2025 validated | yes | partial | no | no | no |
| JSON / text / rich output | yes | no | no | no | no |

## Features

- **17 methods across 5 protocols** - every SAMR, Netlogon, Kerberos kpasswd, LDAP, and RAP path that Windows exposes for changing or resetting a password, including the undocumented diagnostic opnum 63
- **Server 2025 ready** - the AES SAMR change (opnum 73, `SamrUnicodeChangePasswordUser4`) and AES reset (UserInternal7) that Server 2025 requires are both implemented and validated live
- **Strict change vs reset separation** - a change proves the current secret and needs no privilege; a reset is a privileged overwrite that bypasses minimum age and history. Two operations, two subcommands, no confusion
- **Pass-the-hash** - the RC4 and DES SAMR changes accept an NT hash as the old secret, and the set-hash reset writes a hash directly
- **Expired password handling** - when the target password is expired or flagged must-change-at-next-logon, `passwolf change` retries over a null session and completes the change
- **Password policy read** - reads the domain default policy, any applicable fine-grained PSO, and the configured SYSVOL GPO intent, so you see the constraints before you attempt a change
- **Precise error decoding** - every NTSTATUS is decoded so a wrong old password, a policy rejection, and a disabled method are distinguishable
- **Machine-parseable output** - `--format text` (greppable), `--format json` (structured), or `--format pretty` (rich panel)
- **LDAP over sealed 389** - the LDAP paths default to a SASL sign-and-seal bind on port 389, so they work without an LDAPS certificate
- **Spec-traced** - every method is mapped to its Microsoft Open Specification section and validated against live domain controllers (Server 2022 build 20348 and Server 2025 build 26100)

## Change methods (`passwolf change`)

| Method | Protocol / opnum | Auth | Notes |
|---|---|---|---|
| `samr-aes` | SAMR 73, `SamrUnicodeChangePasswordUser4` | password | AES-256; the only SAMR change Server 2025 accepts |
| `samr-rc4` | SAMR 55, `SamrUnicodeChangePasswordUser2` | password, NT hash | legacy RC4; pass-the-hash capable |
| `samr-oem` | SAMR 54, `SamrOemChangePasswordUser2` | password | OEM/LM RC4; needs a stored LM hash and password ≤14 chars |
| `samr-des` | SAMR 38, `SamrChangePasswordUser` | password, NT hash | DES OWF cross-encryption; can set the new password by NT hash |
| `samr-diag` | SAMR 63, `SamrUnicodeChangePasswordUser3` | password | undocumented; returns the structured policy rejection reason |
| `kpasswd` | Kerberos 464, version `0x0001` | password | RFC 3244 change protocol |
| `ldap` | LDAP unicodePwd delete + add | password | defaults to sealed 389, no certificate needed |
| `netlogon-aes` | Netlogon 30, `NetrServerPasswordSet2` | password | machine/trust account, AES over a sealed Netlogon channel |
| `netlogon-des` | Netlogon 6, `NetrServerPasswordSet` | password | machine/trust account, DES OWF; still accepted on Server 2025 |
| `rap` | RAP 115, `NetUserPasswordSet2` over SMB1 | password | obsolete cleartext LM-only; not NTLM-usable on modern hosts |
| `rap-oem` | RAP 214, `SamOEMChangePasswordUser2` over SMB1 | password | legacy OEM/LM RC4; works on SMB1 hosts that store an LM hash |

`auto` is the default. It prefers the strongest SAMR change the DC accepts (AES) and falls back to RC4 only when AES is genuinely unavailable.

### Server 2025 compatibility

| Method | Server 2022 | Server 2025 |
|---|:---:|:---:|
| `samr-aes` | yes | yes |
| `samr-rc4` | yes | blocked |
| `samr-oem` | yes | blocked |
| `samr-des` | yes | blocked |
| `samr-diag` | yes | blocked |
| `kpasswd` | yes | yes |
| `ldap` | yes | yes |
| `netlogon-aes` | yes | yes |
| `netlogon-des` | yes | yes |

Server 2025 blocks the three legacy SAMR changes (RC4, OEM, DES) and the diagnostic opnum as part of its RC4 hardening (CVE-2021-33757 / KB5004605). AES-SAMR, Kerberos, LDAP, and Netlogon remain available.

## Reset methods (`passwolf reset`)

| Method | Protocol / opnum | What it sets | Notes |
|---|---|---|---|
| `samr-aes` | SAMR 58 + UserInternal7 | cleartext password | AES-256 reset (the modern path) |
| `samr-rc4` | SAMR 58 + UserInternal4InformationNew | cleartext password | legacy RC4 + MD5-salt reset |
| `samr-hash` | SAMR 37 + UserInternal1 | NT hash directly | full policy bypass (length, complexity, history, minimum age) |
| `kpasswd` | Kerberos 464, version `0xFF80` | cleartext password | RFC 3244 set protocol, with target name and realm |
| `ldap` | LDAP unicodePwd replace | cleartext password | defaults to sealed 389 |
| `dsrm` | SAMR 66, `SamrSetDSRMPassword` | NT hash | DC-local recovery (RID 500) password; selected with `--dsrm` |

`auto` walks a cross-method ladder (kpasswd, LDAPS, LDAP, then SAMR AES/RC4/hash) and takes the first that succeeds. Unlike changes, no reset method is blocked on Server 2025.

## Policy methods (`passwolf policy`)

Reads the effective password and lockout policy so you can see the constraints a change has to satisfy before you attempt one. 10 methods across 4 protocols, each running independently with its reachability recorded - an anonymous run shows exactly which channels leak the policy and which deny it.

| Method | Protocol | Auth required | What it reads |
|---|---|:---:|---|
| `samr-query` | SAMR opnum 46 (fallback op 8) | yes | domain default: minimum/maximum age, length, history, complexity, reversible encryption, lockout, force-logoff |
| `samr-getdompwinfo` | SAMR opnum 56 | no | handle-light: minimum password length + password properties flags |
| `samr-getusrpwinfo` | SAMR opnum 44 | yes | per-user, PSO-resolved: effective minimum length + properties for `--target-user` |
| `samr-diag` | SAMR opnum 63 | yes | change-failure oracle: submits a guaranteed-violating password and reads the structured rejection (PSO-effective policy of the authenticated principal) |
| `kpasswd` | Kerberos 464 SOFTERROR | yes | change-failure oracle: parses the SOFTERROR policy blob from the KDC (works on Server 2025) |
| `ldap-domain-head` | LDAP domainDNS attributes | yes | most complete single-shot domain-default read: all policy fields from the domain head object |
| `ldap-pso` | LDAP msDS-PasswordSettings | yes | enumerates every fine-grained password settings object (PSO) in the Password Settings Container |
| `ldap-resultant` | LDAP msDS-ResultantPSO | yes | the winning PSO for `--target-user`, dereferenced to its full policy values |
| `ldap-uac` | LDAP msDS-User-Account-Control-Computed | yes | live account state: lockout, password expiry, and bad-password count for `--target-user` |
| `sysvol` | SMB SYSVOL GptTmpl.inf | yes | configured intent per GPO: the `[System Access]` settings from the Default Domain Policy's security template, cross-checked against the live values |

`all` is the default and runs every method. The oracles (`samr-diag`, `kpasswd`) report the policy effective for the authenticated principal. The per-user methods (`samr-getusrpwinfo`, `ldap-resultant`, `ldap-uac`) resolve the fine-grained policy for `--target-user`.

## Example

Self-change on a Server 2025 DC (auto selects the AES change):

```console
$ passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
[+] SNOW/jdoe password changed (samr-aes)
```

## Installation

Install from [PyPI](https://pypi.org/project/passwolf/):

```sh
uv tool install passwolf        # recommended
pip install passwolf             # or with pip
```

Or install from source:

```sh
uv tool install git+https://github.com/StrongWind1/PassWolf
```

Or run from a checkout without installing:

```sh
uv run passwolf change --help
uv run passwolf reset --help
uv run passwolf policy --help
```

## Quick start

```bash
# Self-change on a Server 2025 DC (auto selects the AES opnum 73)
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Pass-the-hash change
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --target-old-hash 47c4cc3a368a4a0fa79a7bf059b7adba --target-new-password 'NewPass1!'

# Set the new password by NT hash (DES change, proves the old secret, no privilege)
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --target-old-password 'OldPass1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Change an expired or must-change-at-next-logon password (retries over a null session)
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --target-old-password 'Expired1!' --target-new-password 'NewPass1!'

# Privileged reset, AES cleartext path, as an admin
passwolf reset --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --auth-as-user Administrator --auth-as-password 'Admin1!' \
    --target-new-password 'NewPass1!'

# Set the NT hash directly (no Kerberos keys regenerated)
passwolf reset --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --auth-as-user Administrator --auth-as-password 'Admin1!' \
    --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Rotate a computer account password over the Netlogon secure channel
passwolf change --target-domain SNOW --target-user 'WS01$' --dc dc.snow.lab \
    --account machine --target-old-password 'curr3nt' --target-new-password 'n3wer' \
    --netbios SNOW

# LDAP change over sealed 389 (works without an LDAPS certificate)
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    --method ldap --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Kerberos bind using the ticket in KRB5CCNAME (no bind password needed)
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab \
    -k --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Read the effective password policy before attempting a change
passwolf policy --target-domain SNOW --dc dc.snow.lab \
    --auth-as-user Administrator --auth-as-password 'Admin1!'
```

## Authentication

All three subcommands bind with NTLM by default, or with Kerberos via `-k` / `--kerberos`. Under `-k` the tool uses the ticket cache named by `KRB5CCNAME` if it holds a usable TGT, otherwise it fetches one from `--dc` with the supplied password or NT hash; either way the interactive bind-password prompt is skipped.

## Output formats

`--format text` (default) prints one greppable status line, `--format json` prints a single JSON object, and `--format pretty` renders a rich panel. The result always decodes the NTSTATUS precisely so a wrong old password, a policy rejection, and a disabled method are distinguishable.

## CLI reference

<details>
<summary><code>passwolf change</code> - change a password by proving the current secret (no privilege required)</summary>

| Argument | Description |
|---|---|
| `--target-user NAME` | (required) the account whose password to change |
| `--target-domain NAME` | (required) the AD domain the account belongs to |
| `--target-old-password PASS` | the current password; prompted if neither this nor `--target-old-hash` is given |
| `--target-old-hash [LM:]NT` | the current NT hash, for a pass-the-hash change |
| `--target-new-password PASS` | the new password; prompted if neither this nor `--target-new-hash` is given |
| `--target-new-hash [LM:]NT` | set the new password by raw NT hash (pins `--method samr-des`; bypasses policy, drops Kerberos keys) |
| `--dc HOST` | domain controller hostname or IP (defaults to `--target-domain`) |
| `--method METHOD` | `auto` (default), `samr-aes`, `samr-rc4`, `samr-oem`, `samr-des`, `samr-diag`, `kpasswd`, `ldap`, `netlogon-aes`, `netlogon-des`, `rap`, `rap-oem` |
| `--account {user,machine,trust}` | account kind (default `user`); `machine` and `trust` route to the Netlogon change |
| `--transport {smb,tcp}` | RPC transport: SMB named pipe (default) or direct TCP |
| `--netbios NAME` | NetBIOS domain name for machine/trust accounts (derived from `--target-domain` if omitted) |
| `--ldaps` | use LDAPS on port 636 instead of sealed LDAP on 389 |
| `--auth-as-user NAME` | authenticate as a different principal (defaults to the target account) |
| `--auth-as-password PASS` | that principal's password |
| `--auth-as-hash [LM:]NT` | that principal's NT hash |
| `--auth-as-domain NAME` | that principal's domain (defaults to `--target-domain`) |
| `-k`, `--kerberos` | bind with Kerberos instead of NTLM; uses `KRB5CCNAME` or fetches a TGT |
| `--format {text,json,pretty}` | output format (default `pretty`) |
| `-v`, `--verbose` | detailed logging |

</details>

<details>
<summary><code>passwolf reset</code> - reset a password by privileged overwrite (requires reset rights)</summary>

| Argument | Description |
|---|---|
| `--target-user NAME` | (required) the account whose password to reset |
| `--target-domain NAME` | (required) the AD domain the account belongs to |
| `--target-new-password PASS` | the new password; prompted if neither this nor `--target-new-hash` is given |
| `--target-new-hash [LM:]NT` | set the NT hash directly (written as `NT` or `LM:NT`; skips length, complexity, history) |
| `--dc HOST` | domain controller hostname or IP (defaults to `--target-domain`) |
| `--auth-as-user NAME` | (required) the privileged account performing the reset |
| `--auth-as-password PASS` | that account's password; prompted if neither this nor `--auth-as-hash` is given |
| `--auth-as-hash [LM:]NT` | that account's NT hash |
| `--auth-as-domain NAME` | that account's domain (defaults to `--target-domain`) |
| `-k`, `--kerberos` | bind with Kerberos instead of NTLM |
| `--method METHOD` | `auto` (default), `samr-aes`, `samr-rc4`, `samr-rc4-unsalted`, `samr-hash`, `kpasswd`, `ldap` |
| `--transport {smb,tcp}` | RPC transport (default `smb`); all SAMR resets are pipe-only |
| `--ldaps` | use LDAPS on port 636 instead of sealed LDAP on 389 |
| `--expire` / `--no-expire` | require (default) or skip a password change at next sign-in |
| `--dsrm` | reset the DC-local Directory Services Restore Mode recovery password instead |
| `--reset-info-class CLASS` | (advanced) send an exact USER_INFORMATION_CLASS: `internal1`, `userall`, `internal4`, `internal5`, `internal4new`, `internal5new`, `internal7`, `internal8` |
| `--reset-opnum {37,58}` | (advanced) pick opnum 37 (`SamrSetInformationUser`) or 58 (`SamrSetInformationUser2`, default); only with `--reset-info-class` |
| `--format {text,json,pretty}` | output format (default `pretty`) |
| `-v`, `--verbose` | detailed logging |

</details>

<details>
<summary><code>passwolf policy</code> - read the password policy (mutates nothing)</summary>

| Argument | Description |
|---|---|
| `--target-domain NAME` | (required) the AD domain to read the policy from |
| `--dc HOST` | domain controller hostname or IP (defaults to `--target-domain`) |
| `--auth-as-user NAME` | the account to sign in as (required unless `--anonymous`) |
| `--auth-as-password PASS` | that account's password |
| `--auth-as-hash [LM:]NT` | that account's NT hash |
| `--auth-as-domain NAME` | that account's domain (defaults to `--target-domain`) |
| `-k`, `--kerberos` | bind with Kerberos instead of NTLM |
| `--anonymous` | connect with no credentials to see what an unauthenticated user can read |
| `--target-user NAME` | resolve this account's fine-grained (PSO) effective policy; defaults to the signed-in principal |
| `--method METHOD` | `all` (default), `samr-query`, `samr-getdompwinfo`, `samr-getusrpwinfo`, `samr-diag`, `kpasswd`, `ldap-domain-head`, `ldap-pso`, `ldap-resultant`, `ldap-uac`, `sysvol` |
| `--transport {smb,tcp}` | RPC transport for the SAMR reads (default `smb`) |
| `--ldaps` | use LDAPS on port 636 instead of sealed LDAP on 389 |
| `--format {text,json,pretty}` | output format (default `pretty`) |
| `-v`, `--verbose` | detailed logging |

</details>

## Development

```bash
git clone https://github.com/StrongWind1/PassWolf.git
cd PassWolf
uv sync                        # install dev dependencies
make check                     # run lint + typecheck + tests + docs
make format                    # auto-fix formatting
```

Conventional commit messages (`feat:`, `fix:`, `docs:`); run `make check` before every commit.

## Credits

Built on [Impacket](https://github.com/fortra/impacket) and [PyCryptodome](https://github.com/Legrandin/pycryptodome). The AES SAMR change (opnum 73) and the AES cleartext reset info levels (UserInternal7) that impacket does not implement are traced directly to the Microsoft Open Specifications ([MS-SAMR], [MS-NRPC], [MS-LSAD], [MS-ADTS]).

## Related tools

Other projects in this collection:

- [AD-SecretGen](https://github.com/StrongWind1/AD-SecretGen) - derive AD password hashes and Kerberos keys from a password
- [NTDSWolf](https://github.com/StrongWind1/NTDSWolf) - offline NTDS.dit parser and credential extractor
- [CredWolf](https://github.com/StrongWind1/CredWolf) - Active Directory credential validation
- [KerbWolf](https://github.com/StrongWind1/KerbWolf) - Kerberos roasting and hash extraction toolkit
- [Kerberos](https://github.com/StrongWind1/Kerberos) - Kerberos in Active Directory: protocol, security, and attacks

## Disclaimer

PassWolf is intended for authorized penetration testing, red team engagements, and security audits only. You must have explicit written permission from the system owner before changing or resetting any account secret in an Active Directory environment. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse or damage caused by this tool.

## License

[Apache License 2.0](LICENSE)
