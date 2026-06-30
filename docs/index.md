# passwolf

Correct, spec-compliant Active Directory password change, reset, and policy read. Three console tools, `passwolf change`, `passwolf reset`, and `passwolf policy`, implement every documented and undocumented Windows method for changing or resetting an account password or hash, and for reading the password policy, over SAMR, Netlogon, LSA, Kerberos kpasswd, LDAP, and SYSVOL. Every method is mapped to its Microsoft Open Specification section and validated against live domain controllers (Windows Server 2022 build 20348 and Server 2025 build 26100).

## Three operations, three tools

A change, a reset, and a read are different operations with different security models, and conflating them is the root of several sharp edges in the bundled tooling. passwolf keeps them apart on purpose.

| Tool | Operation | Proves | Privilege | Touches the account |
|---|---|---|---|---|
| `passwolf change` | change | the current secret (password or NT hash) | none on the target | yes, sets a new secret |
| `passwolf reset` | reset | nothing about the old secret | a caller with reset rights | yes, overwrites the secret |
| `passwolf policy` | read | depends on the channel | none, or anonymous | no, mutates nothing |

A change is subject to the full domain password policy (minimum age, history, complexity). A reset bypasses minimum age and history and requires reset rights. A read never writes, even the methods that probe a change-failure path do so with a guaranteed-rejected password so the account is never modified.

## Why passwolf

impacket's bundled tool can no longer change a password over SAMR on a Windows Server 2025 domain controller: that DC hardens off the legacy RC4 SAMR change opcodes, and impacket never implemented the AES change (`SamrUnicodeChangePasswordUser4`, opnum 73) that replaces them. impacket's non-SAMR change protocols are not gated, so it can still change a password on Server 2025 over LDAP (live-confirmed, where the DC offers LDAPS) or the Kerberos kpasswd protocol; what it cannot do there is a SAMR (NTLM-hash) change. passwolf speaks that AES SAMR change, an LDAP change over sealed 389 that needs no certificate, the AES reset info levels, the undocumented diagnostic change, and a full policy-read surface, none of which impacket models. See [Compared to impacket](internals/impacket.md) for the per-method audit.

## Install

passwolf is managed with [uv](https://docs.astral.sh/uv/).

```
uv tool install git+https://github.com/StrongWind1/passwolf
```

Or run it from a checkout without installing:

```
uv run passwolf change --help
```

## Pick your path

This documentation is written for two readers.

<div class="grid cards" markdown>

- **I just need to use this.**

    Start with [Getting started](guide/getting-started.md), then the per-tool guides for [passwolf change](guide/change.md), [passwolf reset](guide/reset.md), and [passwolf policy](guide/policy.md). [Choosing a method](guide/choosing-a-method.md) explains what each method is for and which to pick, and [Output formats](guide/output-formats.md) covers the pretty, text, and JSON output.

- **I want to know exactly how it works.**

    [Architecture](internals/architecture.md) describes how the app is built and how a request flows end to end. The deep dives cover [crypto and password buffers](internals/crypto.md), every [change method](internals/change-methods.md), [reset method](internals/reset-methods.md), and [policy read method](internals/policy-methods.md) at the wire level, plus [transport and channels](internals/transport.md) and [errors and NTSTATUS](internals/errors.md).

</div>

The [Method matrix](methods.md) is the one-page reference that maps every method to its opnum and spec section.
