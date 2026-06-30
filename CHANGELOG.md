# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog and the project uses semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-06-30

### Added

- `passwolf change` subcommand with the SAMR AES change (opnum 73), the legacy SAMR RC4, OEM, and DES changes (55, 54, 38), the undocumented diagnostic change (63), the Kerberos change protocol, the LDAP unicodePwd change, and the Netlogon machine and trust change (opnums 30 and 6).
- `passwolf reset` subcommand with the SAMR AES cleartext reset (UserInternal7), the legacy RC4 cleartext reset, the set-hash reset (UserInternal1), the DSRM reset (opnum 66), the Kerberos set protocol, the LDAP unicodePwd replace, and the LSA trust-secret set (opnums 138 and 29).
- `passwolf policy` subcommand to read the effective password and lockout policy over SAMR, LDAP, the change-failure oracle, and the SYSVOL GptTmpl.inf templates, covering the domain default and fine-grained (PSO) policies.
- `--target-new-hash` on `passwolf change`: set the new password by NT hash (DES change, proves the old secret, no privilege). It pins `--method samr-des`, is mutually exclusive with `--target-new-password`, bypasses password policy, drops the account's Kerberos keys, and flags the password expired.
- Automatic change of an expired or must-change-at-next-logon password by retrying the SAMR bind over a null session, for the buffer-based methods (`samr-aes`, `samr-rc4`, `samr-oem`, `samr-diag`, and `auto`).
- Kerberos authentication for the bind (`-k` / `--kerberos`) across all subcommands, using the `KRB5CCNAME` ticket cache or fetching a ticket from the DC with the password or NT hash.
- AEAD-AES-256-CBC-HMAC-SHA512 implementations for the SAM and LSAD password buffers, the PBKDF2 content-encryption key derivation, and the RC4, DES OWF, and AES-CFB8 wire constructions, all covered by known-answer tests.
- Precise NTSTATUS decoding and text, JSON, and rich-pretty output formats.
- `auto` method selection: `passwolf change` prefers the AES change and falls back to RC4 only when AES is genuinely unavailable; `passwolf reset` walks a cross-method ladder (kpasswd, LDAPS, LDAP, then the SAMR resets: AES, RC4, RC4-unsalted, set-hash) and takes the first that succeeds.

[Unreleased]: https://github.com/StrongWind1/PassWolf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/StrongWind1/PassWolf/releases/tag/v0.1.0
