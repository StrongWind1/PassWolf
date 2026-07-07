<h1 align="center">PassWolf</h1>

<p align="center">
  Correct, spec-compliant Active Directory password change, reset, and policy read over SAMR, Netlogon, LSA, Kerberos, and LDAP - including the AES paths impacket lacks.
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/PassWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://strongwind1.github.io/PassWolf/"><img src="https://img.shields.io/badge/docs-mkdocs-blue.svg" alt="Docs"></a>
</p>

<p align="center">
  <a href="https://strongwind1.github.io/PassWolf/guide/getting-started/">Getting started</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/guide/choosing-a-method/">Choosing a method</a> &bull;
  <a href="https://strongwind1.github.io/PassWolf/methods/">Method matrix</a>
</p>

One console command, `passwolf`, with three subcommands - `passwolf change`, `passwolf reset`, and `passwolf policy` - that implement every documented and undocumented Windows method for changing or resetting an account password or hash over SAMR, Netlogon, LSA, Kerberos kpasswd, and LDAP, and for reading the effective password policy. A Windows Server 2025 domain controller hardens off the legacy RC4 SAMR change opcodes and accepts only the AES SAMR change (`SamrUnicodeChangePasswordUser4`, opnum 73) in their place; passwolf speaks that AES change, and a good deal more.

## Why separate tools

A change and a reset are different operations with different security models, and conflating them is the root of several sharp edges in the bundled tooling. passwolf keeps them apart on purpose:

- `passwolf change` proves the account's current secret (password or NT hash) and needs no privilege on the target. It is subject to the full domain password policy.
- `passwolf reset` is a privileged overwrite that proves nothing about the old secret. It bypasses minimum password age and history and requires a caller with reset rights.
- `passwolf policy` reads the effective password and lockout policy (the domain policy, any applicable PSO, and the configured SYSVOL GPO intent) so you can see the constraints a change has to satisfy before you attempt one.

## What it covers

Every method below is mapped to its Microsoft Open Specification section and validated against live domain controllers (Server 2022 build 20348 and Server 2025 build 26100).

### Change methods (`passwolf change`)

| Method | Protocol / opnum | Notes |
|---|---|---|
| `samr-aes` | SAMR 73, `SamrUnicodeChangePasswordUser4` | AES; the only SAMR change Server 2025 accepts |
| `samr-rc4` | SAMR 55, `SamrUnicodeChangePasswordUser2` | legacy RC4; pass-the-hash capable |
| `samr-oem` | SAMR 54, `SamrOemChangePasswordUser2` | OEM/LM RC4; needs a stored LM hash and a password ≤14 chars |
| `samr-des` | SAMR 38, `SamrChangePasswordUser` | DES OWF cross-encryption; needs a user handle; can set the new password by NT hash with `--target-new-hash` |
| `samr-diag` | SAMR 63, `SamrUnicodeChangePasswordUser3` | undocumented; returns the structured policy rejection reason |
| `kpasswd` | Kerberos 464, version `0x0001` | RFC 3244 change protocol |
| `ldap` | LDAP unicodePwd delete + add | defaults to sealed 389, no certificate needed |
| `netlogon-aes` | Netlogon 30, `NetrServerPasswordSet2` | machine/trust, AES NL_TRUST_PASSWORD over a sealed channel |
| `netlogon-des` | Netlogon 6, `NetrServerPasswordSet` | machine/trust, DES OWF; still accepted on Server 2025 |
| `rap` | RAP opcode 115, `NetUserPasswordSet2` over SMB1 | obsolete cleartext LM-only path; not NTLM-usable on modern hosts |
| `rap-oem` | RAP opcode 214, `SamOEMChangePasswordUser2` over SMB1 | legacy OEM/LM RC4; works on SMB1 hosts that store an LM hash |

### Reset methods (`passwolf reset`)

| Method | Protocol / opnum | Notes |
|---|---|---|
| `samr-aes` | SAMR 58 + UserInternal7 | AES cleartext reset (the UserInternal7 info level) |
| `samr-rc4` | SAMR 58 + UserInternal4InformationNew | legacy RC4 + MD5-salt cleartext reset |
| `samr-hash` | SAMR 37 + UserInternal1 | set the NT OWF directly (full policy bypass) |
| `kpasswd` | Kerberos 464, version `0xFF80` | RFC 3244 set protocol, with target name and realm |
| `ldap` | LDAP unicodePwd replace | defaults to sealed 389 |
| `dsrm` (`--dsrm`) | SAMR 66, `SamrSetDSRMPassword` | the DC-local recovery (RID 500) password; selected with the dedicated `--dsrm` flag |

`auto` is the default for both operations. For `passwolf change` it prefers the strongest SAMR change the DC accepts (AES) and falls back to RC4 only when AES is genuinely unavailable, never merely for compatibility. For `passwolf reset` it walks a cross-method ladder - kpasswd, LDAPS, LDAP, then the SAMR resets (AES, RC4, RC4-unsalted, set-hash) - and takes the first that succeeds.

On **Windows Server 2025**, the Kerberos set (`kpasswd`), the LDAP `unicodePwd` replace (`ldap`), and the AES SAMR RPC reset (`samr-aes`, `SamrSetInformationUser2` opnum 58 + UserInternal7) all work - confirmed live against a Server 2025 domain controller. The 2025 RC4 hardening (CVE-2021-33757 / KB5004605) blocks the legacy SAMR *changes*, not resets, so no `passwolf reset` method is blocked there.

When the target's password is expired or flagged must-change-at-next-logon, `passwolf change` retries the SAMR bind over a null session and completes the change. This covers the buffer-based methods (`samr-aes`, `samr-rc4`, `samr-oem`, `samr-diag`, and `auto`); the handle-based `samr-des` cannot use the null-session path.

### Authentication

All three subcommands bind with NTLM by default, or with Kerberos via `-k` / `--kerberos`. Under `-k` the tool uses the ticket cache named by `KRB5CCNAME` if it holds a usable TGT, otherwise it fetches one from `--dc` with the supplied password or NT hash; either way the interactive bind-password prompt is skipped.

## Installation

passwolf is managed with [uv](https://docs.astral.sh/uv/).

```
uv tool install git+https://github.com/StrongWind1/PassWolf
```

Or run it from a checkout without installing:

```
uv run passwolf change --help
uv run passwolf reset --help
uv run passwolf policy --help
```

## Examples

```
# Self-change on a Server 2025 DC (auto selects the AES opnum 73).
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Pass-the-hash change.
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab --target-old-hash 47c4cc3a368a4a0fa79a7bf059b7adba --target-new-password 'NewPass1!'

# Set the new password by NT hash on a change (DES change, proves the old secret, no privilege).
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab --target-old-password 'OldPass1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Change an expired or must-change-at-next-logon password (retries over a null session).
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab --target-old-password 'Expired1!' --target-new-password 'NewPass1!'

# Privileged reset, AES cleartext path, as an admin.
passwolf reset --target-domain SNOW --target-user jdoe --dc dc.snow.lab --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'

# Set the NT hash directly (no Kerberos keys regenerated).
passwolf reset --target-domain SNOW --target-user jdoe --dc dc.snow.lab --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-hash 47c4cc3a368a4a0fa79a7bf059b7adba

# Rotate a computer account password over the Netlogon secure channel.
passwolf change --target-domain SNOW --target-user 'WS01$' --dc dc.snow.lab --account machine --target-old-password 'curr3nt' --target-new-password 'n3wer' --netbios SNOW

# LDAP change over sealed 389 (works without an LDAPS certificate).
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab --method ldap --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'

# Kerberos bind using the ticket in KRB5CCNAME (no bind password needed).
passwolf change --target-domain SNOW --target-user jdoe --dc dc.snow.lab -k --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
```

## Output formats

`--format text` (default) prints one greppable status line, `--format json` prints a single JSON object, and `--format pretty` renders a rich panel. The result always decodes the NTSTATUS precisely so a wrong old password, a policy rejection, and a disabled method are distinguishable.

## What sets it apart

- The AES change (opnum 73) and the AES reset info levels (UserInternal7) are what a Server 2025 DC requires, and both are implemented here.
- The LDAP path defaults to plain 389 with a SASL sign-and-seal bind, so it works without an LDAPS certificate instead of requiring `ldaps://`.
- The undocumented SAMR opnum 63 returns the structured reason a change was rejected.
- Precise NTSTATUS decoding and a strict change-versus-reset separation.

## Limitations and notes

- The reset cleartext info levels use the SMB session key as their content-encryption key, so they require the SMB named-pipe transport, not direct TCP.
- The OEM change and the LDAP change need the cleartext old password (the LM hash and the unicodePwd delete value cannot be formed from an NT hash).
- Netlogon and the DSRM reset address machine/trust and the RID-500 recovery account respectively, not arbitrary users.

## Development

```
make install-dev   # uv sync
make check         # ruff check + ruff format --check + ty + pytest + docs
make format        # ruff format + ruff check --fix
```

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
