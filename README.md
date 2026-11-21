<h1 align="center">PassWolf</h1>

<p align="center"><strong>Change or reset any AD password, and read the policy, over every method Windows supports. Including the AES paths Server 2025 requires.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/passwolf/"><img src="https://img.shields.io/pypi/v/passwolf.svg" alt="PyPI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind.dev/PassWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind.dev/PassWolf/guide/getting-started/#install">Installation</a> &bull;
  <a href="https://strongwind.dev/PassWolf/guide/getting-started/#first-run">Quick start</a> &bull;
  <a href="https://strongwind.dev/PassWolf/methods/">Method matrix</a> &bull;
  <a href="https://strongwind.dev/PassWolf/">Documentation</a>
</p>

---

PassWolf changes or resets an Active Directory account password, and reads the effective password policy, over SAMR, Netlogon, Kerberos kpasswd, and LDAP, from one command with three subcommands: `passwolf change`, `passwolf reset`, and `passwolf policy`. Existing tools each cover a few of these paths and skip the rest; PassWolf implements every documented and undocumented one. That includes the AES SAMR change that Windows Server 2025 requires, which no other public tool implements.

## Example

Change your own password. `auto` picks the strongest method the DC accepts; on Server 2025 that is the AES SAMR change (opnum 73), the only SAMR change it still accepts.

```sh
passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
```

## Features

- **Server 2025 ready**: the AES SAMR change (opnum 73, `SamrUnicodeChangePasswordUser4`) that Server 2025 requires and the AES reset (UserInternal7), both validated live. Server 2025 blocks the RC4, OEM, and DES SAMR changes and the diagnostic opnum 63 (CVE-2021-33757 / KB5004605); `auto` routes around them, and Kerberos, LDAP, and Netlogon stay available.
- **Every method**: 11 change methods, 7 reset methods, and 10 policy reads across SAMR, Netlogon, Kerberos kpasswd, LDAP, RAP, and SYSVOL, including the undocumented diagnostic change (opnum 63), Netlogon machine and trust rotation, and the DSRM recovery account. The LDAP paths default to a sealed bind on 389, so they work without an LDAPS certificate.
- **Change and reset kept apart**: a change proves the current secret and needs no privilege; a reset is a privileged overwrite that bypasses minimum age and history. Each has its own subcommand, and `passwolf policy` never writes.
- **Automatic selection with fallback**: `auto` (the default) prefers the AES SAMR change and drops to RC4 only when AES is unavailable; a reset tries kpasswd, LDAPS, LDAP, then SAMR AES, RC4, and set-hash. An expired or must-change-at-next-logon password is changed over a null session.
- **Pass-the-hash**: the AES, RC4, and DES SAMR changes accept an NT hash as the old secret, the DES change can set the new password by NT hash, and the set-hash reset writes a hash directly.
- **Policy read**: the domain default, every fine-grained PSO, the resultant PSO for a given user, and the SYSVOL GPO intent, with each channel's reachability recorded, so an anonymous run shows which channels leak the policy.
- **Precise results**: every NTSTATUS is decoded, so a wrong old password, a policy rejection, and a disabled method are distinguishable. Output as `--format pretty` (default), `text`, or `json`.
- **Spec-traced**: every method is mapped to its Microsoft Open Specification section and validated against live domain controllers (Server 2022 build 20348 and Server 2025 build 26100).

Every method with its opnum, spec section, and Server 2025 status: [Method matrix](https://strongwind.dev/PassWolf/methods/). Which one to pick: [Choosing a method](https://strongwind.dev/PassWolf/guide/choosing-a-method/).

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

## Quick start

```sh
# Pass-the-hash change
passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local \
    --target-old-hash 47c4cc3a368a4a0fa79a7bf059b7adba --target-new-password 'NewPass1!'

# Bind with Kerberos using the ticket in KRB5CCNAME (no bind password needed)
passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local \
    -k --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Rotate a computer account password over the Netlogon secure channel
passwolf change --target-domain corp.local --target-user 'WS01$' --dc dc01.corp.local \
    --account machine --target-old-password 'curr3nt' --target-new-password 'n3wer' --netbios CORP

# Privileged reset as an admin
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local \
    --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'

# Set the NT hash directly (no Kerberos keys regenerated)
passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local \
    --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Read the effective password policy before attempting a change
passwolf policy --target-domain corp.local --dc dc01.corp.local \
    --auth-as-user Administrator --auth-as-password 'Admin1!'
```

Every option and more examples per subcommand: [passwolf change](https://strongwind.dev/PassWolf/guide/change/), [passwolf reset](https://strongwind.dev/PassWolf/guide/reset/), [passwolf policy](https://strongwind.dev/PassWolf/guide/policy/). NTLM and Kerberos binds: [Getting started](https://strongwind.dev/PassWolf/guide/getting-started/#how-each-tool-authenticates). Output fields and JSON keys: [Output formats](https://strongwind.dev/PassWolf/guide/output-formats/).

## Compared to other tools

The per-method wire audit against impacket is in [Compared to impacket](https://strongwind.dev/PassWolf/internals/impacket/).

| Capability | PassWolf | impacket | bloodyAD | NetExec | rpcclient |
| --- | :---: | :---: | :---: | :---: | :---: |
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

## Development

```sh
git clone https://github.com/StrongWind1/PassWolf.git && cd PassWolf
uv sync                        # install dev dependencies
make check                     # run lint + typecheck + tests + docs
make format                    # auto-fix formatting
```

Conventional commit messages (`feat:`, `fix:`, `docs:`); run `make check` before every commit.

## Credits

Built on [Impacket](https://github.com/fortra/impacket), [PyCryptodome](https://github.com/Legrandin/pycryptodome), and [Rich](https://github.com/Textualize/rich). The AES SAMR change (opnum 73) and the AES cleartext reset info levels (UserInternal7) that impacket does not implement are traced directly to the Microsoft Open Specifications ([MS-SAMR], [MS-NRPC], [MS-LSAD], [MS-ADTS]).

## Related tools

- [**CredWolf**](https://github.com/StrongWind1/CredWolf): Validate AD passwords, hashes, keys, and tickets over NTLM and Kerberos
- [**KerbWolf**](https://github.com/StrongWind1/KerbWolf): Kerberos roasting and TGT attack toolkit for Active Directory
- [**NTDSWolf**](https://github.com/StrongWind1/NTDSWolf): Offline NTDS.dit parser and credential extractor for NT/LM hashes, Kerberos keys, LAPS, and gMSA
- [**AD-SecretGen**](https://github.com/StrongWind1/AD-SecretGen): Derive every password-derived AD secret (NT/LM, Kerberos keys, WDigest) from a password
- [**ntcompress**](https://github.com/StrongWind1/ntcompress): Pure-Python ESE record compression and ntdll RtlCompressBuffer/RtlDecompressBuffer formats
- [**Kerberos**](https://github.com/StrongWind1/Kerberos): Protocol internals, security configuration, and attack techniques for Kerberos in Active Directory

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

PassWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
