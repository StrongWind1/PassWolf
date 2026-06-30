# passwolf policy: read the policy

`passwolf policy` reads the Active Directory password and lockout policy. It is the third passwolf operation, separate from changing and resetting a password, and it mutates nothing: there is no code path in this tool that can write a secret. It gathers the domain-wide default policy over every channel a domain controller exposes it on, resolves a named account's fine-grained (PSO) effective policy, and reports which channels answered and which were denied. Every value carries a scope label so the domain default and a per-user fine-grained policy are never confused.

!!! note "Read-only by design"
    `passwolf policy` never changes a password. The two oracle methods (`samr-diag` over opnum 63, and `kpasswd`) submit a deliberately policy-violating probe password so the server returns the policy in its rejection, and the change is never applied. An unexpected success is reported as a failure rather than silently accepted. See [Oracle read-safety](#oracle-read-safety) below.

## What it does

A single run fans out across up to ten independent reads. The domain-default reads (`samr-query`, `samr-getdompwinfo`, `ldap-domain-head`, `sysvol`) report the policy that governs any account without a PSO. The fine-grained reads (`samr-getusrpwinfo`, `samr-diag`, `kpasswd`, `ldap-pso`, `ldap-resultant`, `ldap-uac`) resolve a per-user effective policy or live account state. Each method runs on its own and its reachability verdict is recorded, so an anonymous probe shows exactly which channels leak the policy and which deny it rather than collapsing to one answer.

For the protocol depth (opnums, structs, spec sections, and crypto behind each read) see [Policy methods](../internals/policy-methods.md) and the method matrix at [Methods](../methods.md). For a per-task method picker see [Choosing a method](choosing-a-method.md).

## Domain versus PSO

Every policy value is labelled with one of three scopes, and the labels are the whole point of running multiple channels at once:

| Scope | Meaning | Methods that report it |
|---|---|---|
| `domain` | The domain-wide default that governs any account without a PSO. | `samr-query`, `samr-getdompwinfo`, `ldap-domain-head`, `sysvol` |
| `PSO` | A fine-grained Password Settings Object value. Three of these reads (`samr-getusrpwinfo`, `samr-diag`, `kpasswd`) resolve the per-user effective policy, so when no PSO applies their values equal the domain default; `ldap-resultant` resolves the winning PSO DN and reports no policy values when no PSO is bound; `ldap-pso` enumerates every PSO object in the container verbatim, regardless of subject. | `samr-getusrpwinfo`, `samr-diag`, `kpasswd`, `ldap-pso`, `ldap-resultant` |
| `account` | Live per-user account state (lockout, expiry, bad-password count), not a policy. | `ldap-uac` |

A PSO makes the three per-user effective reads (`samr-getusrpwinfo`, `samr-diag`, `kpasswd`) report a different minimum length, history, or lockout threshold than the domain reads. Laying every method side by side in one table is what makes that disagreement visible.

## Options

Run `uv run passwolf policy --help` for the authoritative list. Every option is documented below. `--target-domain` is strictly required: `argparse` rejects a run without it, since it names the domain the tool reads. `--dc` is optional and defaults to the `--target-domain` value, so pass it only when the DC host differs from the domain name. One more constraint is enforced at runtime: you must decide how to bind by supplying either `--auth-as-user` or `--anonymous`. Everything else is optional.

This summary table fixes each option's status; the per-option prose below repeats it:

| Option | Required / optional |
|---|---|
| `--target-domain` | Required. |
| `--dc` | Optional; defaults to `--target-domain`. |
| `--auth-as-user` | Required: give this or `--anonymous`. |
| `--anonymous` | Required: give this or `--auth-as-user`. |
| `--auth-as-password` | Optional. |
| `--auth-as-hash` | Optional. |
| `--auth-as-domain` | Optional. |
| `-k` / `--kerberos` | Optional. |
| `--target-user` | Optional. |
| `--method` | Optional. |
| `--transport` | Optional. |
| `--ldaps` | Optional. |
| `--format` | Optional. |
| `-v` / `--verbose` | Optional. |

### Target

- `--dc DC` the domain controller to read from, by hostname or address. Optional; when omitted it defaults to the `--target-domain` value, so supplying `--target-domain` alone covers it. Pass `--dc` directly when the DC host differs from the domain name.

### Authentication

Authentication comes solely from these flags. There is no separate subject credential: the same principal authenticates every read. You must choose how to bind: give either `--auth-as-user` to sign in as a named account or `--anonymous` to bind with a null session.

- `--auth-as-user USER` the principal to authenticate as. Required: give this or `--anonymous`.
- `--auth-as-password PASS` the password for that principal. Optional. If you give `--auth-as-user` with neither `--auth-as-password` nor `--auth-as-hash`, the tool prompts for the password and reads it from the terminal without echo, which keeps the secret off the command line and out of the process list. (`--anonymous` runs need no password and are never prompted.)
- `--target-domain DNS` the DNS domain to authenticate against, such as `corp.local`. Required. It is also used for the LDAP, Kerberos, and SYSVOL reads, so it is what those channels target. A separate `--auth-as-domain` flag sets the bound principal's domain for cross-domain auth and defaults to `--target-domain`.
- `--auth-as-hash [LM:]NT` the NT hash for the principal, for a pass-the-hash bind instead of a password. Optional.
- `--auth-as-domain DOMAIN` the bound principal's domain, for cross-domain auth. Optional; defaults to `--target-domain`.
- `--anonymous` bind with a null session, with no credentials. Required: give this or `--auth-as-user`. An anonymous bind has no principal, so the per-user and oracle methods are skipped (see the anonymous probe under [Examples](#examples)).
- `-k` / `--kerberos` bind the `--auth-as-user` principal with Kerberos instead of NTLM. Optional. When the `KRB5CCNAME` environment variable points to a usable ticket cache, the TGT in it is used and the run needs no password at all, so `-k` suppresses the password prompt; otherwise a TGT is requested from the KDC, which is the `--dc` host, using `--auth-as-password` or `--auth-as-hash`, either of which you may still pass with `-k` to fetch a fresh ticket. It governs only how the session binds, not which methods run. `--anonymous` is a null session and ignores `-k`.

### Fine-grained policy

- `--target-user USER` resolve this account's fine-grained (PSO) effective policy. Optional; defaults to the authenticated principal (`--auth-as-user`), so an authenticated run reads its own effective policy with no extra flag. No secret for this account is needed: the `--target-user` reads (`samr-getusrpwinfo`, `ldap-resultant`, `ldap-uac`) open or query the object rather than prove a change. An anonymous run, having no principal, resolves no per-user policy.

### Method selection

- `--method METHOD` the read method to run, or `all` (the default). Optional. The full list is below.
- `--transport {smb,tcp}` the transport for the SAMR reads. Optional. Default `smb` (the named pipe); `tcp` uses a direct DCE/RPC connection. This affects only the four SAMR methods.
- `--ldaps` use LDAPS on 636 for the LDAP reads instead of the default sealed LDAP on 389. Optional. There is no LDAPS requirement: sealed 389 uses SASL sign and seal and needs no certificate. Use `--ldaps` only when a certificate is present and you specifically want 636.

The `--method` choices, exactly as the tool exposes them:

| Method | Scope | What it reads |
|---|---|---|
| `all` | (every method) | The default: run all ten reads. |
| `samr-query` | domain | SAMR domain-query classes over opnum 46 (with opnum 8 fallback): the full default-domain policy. |
| `samr-getdompwinfo` | domain | SAMR GetDomainPasswordInformation over opnum 56: a handle-light read of length and properties. |
| `samr-getusrpwinfo` | PSO | SAMR GetUserDomainPasswordInformation over opnum 44 for `--target-user`: PSO-effective length and properties. |
| `samr-diag` | PSO | The opnum-63 change-failure oracle: the full effective policy for the authenticated principal. |
| `kpasswd` | PSO | The Kerberos kpasswd SOFTERROR oracle: the effective policy for the authenticated principal. |
| `ldap-domain-head` | domain | LDAP attributes on the domain head: the most complete single domain read. |
| `ldap-pso` | PSO | Every Password Settings Object in the container, with complexity and reversible as explicit booleans. |
| `ldap-resultant` | PSO | `msDS-ResultantPSO` for `--target-user`: the winning PSO DN, dereferenced. |
| `ldap-uac` | account | `msDS-User-Account-Control-Computed` for `--target-user`: live lockout, expiry, and bad-password count. |
| `sysvol` | domain | The SYSVOL `GptTmpl.inf` security templates: the GPO configured intent. |

See [Policy methods](../internals/policy-methods.md) for each method's opnum, struct, and spec section.

### Output

- `--format {text,json,pretty}` the output format. Optional; the default is **pretty**. See [How to read the output](#how-to-read-the-output) and the [Output formats](output-formats.md) guide.
- `-v` / `--verbose` enable debug logging on stderr. Optional.

## How to read the output

The default format is `pretty`. It is a boxed dashboard. (`text` renders the same structure as greppable indented sections; `json` carries the same data under stable snake_case keys. Both are covered in [Output formats](output-formats.md).)

### The methods comparison table

The centerpiece is the `methods` table: one row per method that ran, laid out in aligned columns.

- **method** the method identifier (`samr-query`, `kpasswd`, and so on).
- **scope** `domain`, `PSO`, or `account`. In pretty output this cell is colored: domain is blue, PSO is magenta, account is yellow.
- **status** the short reachability verdict: `ok`, `denied`, `unavailable`, `failed`, or `skipped`. Colored green for `ok`, red for a failure or denial, yellow for `skipped`. The full reason lives in the reachability section below.
- The per-field columns, one for every policy value, so you can compare every method at a glance: `min len`, `history`, `max age (d)`, `min age (d)`, `complexity`, `reversible`, `lockout thr`, `lockout dur (m)`, `lockout reset (m)`, and `force logoff (s)`. The unit suffixes mark days, minutes, and seconds, and the three lockout columns are the threshold, the duration, and the reset-counter window in that order. A method that does not carry a given field shows `-` there.

When a PSO is in play, the `PSO`-scope rows show a different `min len` or `lockout thr` than the `domain`-scope rows, and the table is where that difference is visible.

### The detail blocks

Below the table the detail is grouped by scope, one compact box each:

- **domain password policy** the most complete domain-default record.
- **PSO (fine-grained) effective policy** the most complete per-user effective record.
- **target user** the `--target-user` view: resultant PSO DN, effective minimum length and complexity, and live state (locked out, password expired, bad-password count). A **winning PSO** box follows when one applies.
- One box per enumerated **PSO object** (from `ldap-pso`) and per **GPO configured intent** (from `sysvol`).

In every detail block each field is labelled with the official Microsoft Group Policy name (as it appears in `secpol.msc` and the Microsoft Learn password and account-lockout policy pages), with the protocol field it was read from in parentheses where the box exposes it as a distinct field, so the label is both admin-recognizable and traceable to the wire.

??? note "Field labels you will see"
    | Display label (with source field) | Meaning |
    |---|---|
    | `Minimum password length (MinPasswordLength)` | Domain minimum length, from the SAMR domain struct. |
    | `Enforce password history (PasswordHistoryLength)` | How many old passwords are remembered. |
    | `Maximum password age (MaxPasswordAge)` | Carried with its unit, for example `42 days`. |
    | `Minimum password age (MinPasswordAge)` | The lockin window before a password can be changed again. |
    | `Password must meet complexity requirements` | `enabled`, `disabled`, or `unknown`; shown as its own row, with no parenthetical source field because the value is decoded from the packed `Password properties (PasswordProperties)` bits, which are also shown as their own row. |
    | `Store passwords using reversible encryption` | Tri-state flag; shown as its own row, with no parenthetical source field because the value is decoded from the packed `Password properties (PasswordProperties)` bits. |
    | `Account lockout threshold (LockoutThreshold)` | Bad attempts before lockout. |
    | `Account lockout duration (LockoutDuration)` | Carried in minutes, for example `10 min`. |
    | `Reset account lockout counter after (LockoutObservationWindow)` | The observation window, in minutes. |
    | `Force logoff (ForceLogoff)` | In seconds. |

    A PSO box uses the `msDS-` attribute names instead (`msDS-MinimumPasswordLength`, `msDS-LockoutThreshold`, and so on) and adds `Precedence (msDS-PasswordSettingsPrecedence)` and `Applies to (msDS-PSOAppliesTo)`. A SYSVOL box uses the `GptTmpl.inf` keys (`MinimumPasswordLength`, `LockoutBadCount`, `ResetLockoutCount`).

### The reachability section

A `not reached` box lists every method that did not return `ok`, with its full reason: `denied`, `unavailable: <detail>`, `failed: <detail>`, or `skipped: <reason>` (for example `skipped: no --target-user` or `skipped: needs authentication`). On a successful run where everything answered, this box is absent. The reachability map is what makes an anonymous probe useful.

!!! tip "Exit status"
    `passwolf policy` exits `0` when at least one method returned policy data, `1` when every method was denied or unavailable, and `2` on a usage error. That makes it scriptable: a `0` means you got policy, a `1` means the DC leaked nothing on the channels you tried.

## Oracle read-safety

Two methods are change-failure oracles, and both are read-safe.

`samr-diag` (opnum 63) and `kpasswd` submit a deliberately policy-violating new password: a short control string that no policy can accept. The server rejects it and, in rejecting it, returns the policy that would have applied. The probed account is never modified. If the submission were to succeed unexpectedly, that success is reported as a failure so you can investigate the account rather than silently accept a write.

Both oracles prove identity as the principal you authenticate with, since proving a change requires that principal's own secret. They therefore report the policy effective for `--auth-as-user`, not for an arbitrary `--target-user`. To read a specific account's PSO-effective policy through the oracles, authenticate as that account.

!!! warning "The two oracles diverge across server versions"
    Opnum 63 is the legacy RC4 change, so Server 2025 refuses it with `STATUS_ACCESS_DENIED` (the CVE-2021-33757 gate) and `samr-diag` is reported as denied there. The `kpasswd` SOFTERROR path is not RC4-gated and works on Server 2025, so it is the oracle that survives modern hardening. Both draw the same policy by different routes. See [Policy methods](../internals/policy-methods.md) for the wire detail.

## Examples

=== "Self (authenticated)"

    Read the domain default and your own effective policy as a low-privileged user. `--target-user` defaults to `--auth-as-user`, so this reads `jdoe`'s effective policy with no extra flag.

    ```console
    $ uv run passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe --auth-as-password 'Passw0rd!'
    ```

=== "Anonymous probe"

    Probe with a null session to see which channels leak the policy on this DC. The per-user and oracle methods are skipped (no principal), and the reachability section becomes the result.

    ```console
    $ uv run passwolf policy --dc dc01.corp.local --target-domain corp.local --anonymous
    ```

=== "Another account's PSO"

    Resolve a different account's fine-grained effective policy. No secret for `jdoe` is needed: the per-user reads open or query the object.

    ```console
    $ uv run passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --target-user jdoe
    ```

=== "Kerberos bind"

    Bind the `--auth-as-user` principal with Kerberos. With a TGT already in `KRB5CCNAME` the run needs no password.

    ```console
    $ uv run passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe -k
    ```

=== "ldap-pso as JSON"

    Enumerate the fine-grained Password Settings Objects and emit JSON for a machine consumer.

    ```console
    $ uv run passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user Administrator --auth-as-password 'Admin1!' --method ldap-pso --format json
    ```

!!! danger "Credentials on the command line"
    A password passed with `--auth-as-password` may be visible to other local users through the process list. Prefer `--auth-as-hash` for a pass-the-hash bind, or run from a host where the process table is not exposed.

## See also

- [Choosing a method](choosing-a-method.md) for picking a single `--method` per task.
- [Output formats](output-formats.md) for the text, JSON, and pretty layouts in full.
- [Policy methods](../internals/policy-methods.md) for the opnums, structs, and spec sections behind each read.
- [Methods](../methods.md) for the full cross-tool method matrix.
