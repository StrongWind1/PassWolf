# Getting started

passwolf is three console tools for Active Directory password operations: `passwolf change` changes a password by proving the current secret, `passwolf reset` overwrites a password as a privileged caller, and `passwolf policy` reads the password policy without writing anything. This page covers installing the tools, how each one names its target and takes its credentials, what the output and exit codes mean, and a first command for each tool. If you are deciding which change or reset method to pin, read [Choosing a method](choosing-a-method.md) next; for the full per-tool option reference see [passwolf change](change.md), [passwolf reset](reset.md), and [passwolf policy](policy.md).

## Install

passwolf is managed with [uv](https://docs.astral.sh/uv/). There are two ways to get the tools on your path.

=== "Install the tools"

    Install the console scripts so `passwolf change`, `passwolf reset`, and `passwolf policy` are on your PATH:

    ```
    uv tool install git+https://github.com/StrongWind1/passwolf
    ```

    After this the three commands run directly:

    ```
    passwolf change --help
    passwolf reset --help
    passwolf policy --help
    ```

=== "Run from a checkout"

    Clone the repository and run the tools through `uv run` without installing them:

    ```
    uv run passwolf change --help
    uv run passwolf reset --help
    uv run passwolf policy --help
    ```

The examples below show the bare command names. If you are running from a checkout, prefix each one with `uv run`.

## Naming the target

`passwolf change` and `passwolf reset` name the account to act on with `--target-domain` and `--target-user`, and the domain controller to reach with `--dc`. `--target-domain` is required for all three tools. `passwolf policy` is similar: it takes the DC with `--dc` and learns the domain from `--target-domain`.

### passwolf change and passwolf reset: `--target-domain`, `--target-user`, `--dc`

The account is named explicitly with `--target-domain DOMAIN` and `--target-user USER`, and the domain controller with `--dc DC`. `--target-domain` is required. `--dc` is optional; when omitted it defaults to `--target-domain`.

| You type | Domain | User | DC |
|---|---|---|---|
| `--target-domain corp.local --target-user jdoe --dc dc01.corp.local` | `corp.local` | `jdoe` | `dc01.corp.local` |
| `--target-domain corp.local --target-user jdoe` (DC defaults to the domain) | `corp.local` | `jdoe` | `corp.local` |

!!! note "Quoting machine accounts"
    A machine account name ends in `$`, which the shell may treat as a variable. Quote the user value, for example `--target-user 'WS01$'`. This applies to `passwolf change --account machine` and `--account trust`.

### passwolf policy: `--dc` plus `--target-domain`

`passwolf policy` reads from one DC, named with `--dc` (hostname or address). The domain is a separate option, `--target-domain`, and it is also the domain used for the LDAP, Kerberos, and SYSVOL reads.

```
passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe --auth-as-password 'Passw0rd!'
```

## How each tool authenticates

The three tools have different credential models because they are different operations. Match the credential flags to the tool. If you omit any password flag (a change's old or new password, a reset's new password, or `--auth-as-password`), the tool prompts for it on the terminal without echo, which keeps the secret off the command line and out of the process list.

All three tools accept `-k` / `--kerberos` to bind with Kerberos instead of NTLM. With `-k`, the tool uses an existing ticket from the cache named by the `KRB5CCNAME` environment variable, or fetches a TGT from the `--dc` host with the supplied password or NT hash. Because the cache can supply the credential, `-k` skips the interactive prompt for the bind password; it changes only how the session authenticates, not the password being changed or set.

=== "passwolf change (change)"

    A change proves the account's **current** secret and needs no privilege on the target. Supply the current credential one of two ways:

    - `--target-old-password PASS`: the account's current cleartext password.
    - `--target-old-hash [LM:]NT`: the account's current NT hash, for a pass-the-hash change.

    By default `passwolf change` binds as the target account itself using that old secret, so no separate caller is needed. The optional `--auth-as-user USER` with `--auth-as-password PASS` binds the SAMR or LDAP session as a different principal when the change path requires it.

    The new secret is normally `--target-new-password PASS` (cleartext). As an alternative, `--target-new-hash [LM:]NT` sets the new password directly by NT hash on the DES change; it pins `--method samr-des`, is mutually exclusive with `--target-new-password`, and still proves the old secret without any privilege.

    An expired password, or one flagged must-change-at-next-logon, can still be changed: `passwolf change` retries the SAMR bind over a null session automatically and completes the change for the buffer-based methods (`samr-aes`, `samr-rc4`, `samr-oem`, `samr-diag`, and `auto`).

    !!! note "The LDAP method is the one exception to requiring an old credential up front"
        For `--method ldap`, `passwolf change` accepts a run without `--target-old-password`/`--target-old-hash` because the LDAP change is driven by `--auth-as-user`. Every other method requires the old credential, per the check in `src/passwolf/change.py`.

=== "passwolf reset (reset)"

    A reset proves **nothing** about the old password; it is a privileged overwrite. It requires a caller with reset rights on the target, supplied with `--auth-as-user`:

    - `--auth-as-user USER` (required): the caller account with reset rights; pair it with `--auth-as-password PASS`, or omit the password and you are prompted for it without echo.
    - `--auth-as-hash [LM:]NT`: the caller's NT hash, for a pass-the-hash bind instead of a password.
    - `--auth-as-domain DNS`: the caller's domain, if it differs from the target domain; it defaults to `--target-domain`.

    The new secret is separate from the caller credential. Supply exactly one of `--target-new-password PASS` (cleartext, for the cleartext methods) or `--target-new-hash [LM:]NT` (for the set-hash reset, which writes the NT, and optionally LM, one-way function directly).

=== "passwolf policy (read)"

    A read mutates nothing. It authenticates with `--auth-as-user`/`--auth-as-password`/`--target-domain` (or a pass-the-hash bind with `--auth-as-hash`), or it runs `--anonymous` with a null session and no credentials:

    - `--auth-as-user USER` with `--auth-as-password PASS` and `--target-domain DNS`: an authenticated bind.
    - `--auth-as-hash [LM:]NT`: the NT hash for the authenticating principal, for a pass-the-hash bind.
    - `--anonymous`: bind with a null session.

    An anonymous run skips the methods that need an identity (the opnum-63 and Kerberos kpasswd change-failure oracles, which report the policy effective for the authenticated principal) and shows exactly which channels still leak the policy. `--target-user` resolves another account's fine-grained (PSO) effective policy and defaults to the principal you authenticate as.

## Output

All three tools default to the `pretty` format, which renders a rich panel or table. The `--format` option also accepts `text` (one greppable status line) and `json` (a single JSON object). The default changed recently: it is now `pretty`, not `text`. For a field-by-field walkthrough of each format, see [Output formats](output-formats.md).

```
--format {text,json,pretty}    # default pretty
```

## Exit codes

Every tool returns a meaningful exit status so it can be driven from a script.

| Code | `passwolf change` / `passwolf reset` | `passwolf policy` |
|---|---|---|
| 0 | the change or reset succeeded | at least one read method returned policy data |
| 1 | the method failed or was unavailable on this DC | every method was denied or unavailable |
| 2 | a usage error (bad arguments) | a usage error (bad arguments) |

The meaning of 2 is identical across the tools: it is an argument or usage error, raised before any network call. Code 1 covers both a method the DC rejected and a method the DC does not expose. For `passwolf policy`, code 0 means progress, not completeness: it is returned when any single channel returned data, even if others were denied, because each method's reachability is reported independently.

## Credentials and the process list

!!! warning "Command-line credentials are visible to other local users"
    Passwords and hashes passed as command-line arguments may be visible to other users on the same host through the process list (for example `ps`, `/proc`, or process-monitoring tools). On a shared or multi-user machine, prefer a pass-the-hash flag where the secret is less sensitive, run from a host only you control, or be aware that the argument is exposed for the lifetime of the process. Every tool prints this same note in its `--help` epilog.

## First run

One starting command per tool. Replace the domain, DC, user, and secrets with your own.

=== "Change your own password"

    `passwolf change` with `auto` (the default method) picks the strongest change the DC accepts:

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
    ```

    Continue with [passwolf change](change.md).

=== "Reset another account"

    `passwolf reset` as a privileged caller overwrites the target's password:

    ```
    passwolf reset --target-domain corp.local --target-user jdoe --dc dc01.corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-new-password 'NewPass1!'
    ```

    Continue with [passwolf reset](reset.md).

=== "Read the policy"

    `passwolf policy` as a low-privileged user reads the domain default and your own effective policy:

    ```
    passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe --auth-as-password 'Passw0rd!'
    ```

    Continue with [passwolf policy](policy.md).
