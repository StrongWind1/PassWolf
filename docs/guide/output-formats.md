# Output formats

Every passwolf tool renders the same result through one of three formatters, chosen with `--format`: `pretty`, `text`, or `json`. The choices come straight from the `OutputFormat` enum in `src/passwolf/model.py`, and the rendering lives in `src/passwolf/console.py`. `passwolf change` and `passwolf reset` emit a single change/reset outcome; `passwolf policy` emits a richer policy read. The format flag works the same way on all three.

!!! note "pretty is the default"
    The default format is now `pretty` (this changed recently). `passwolf change --help`, `passwolf reset --help`, and `passwolf policy --help` all show `output format (default pretty)`. Pass `--format text` or `--format json` when you want a greppable line or a machine-readable object instead.

## The three formats at a glance

| Format | Shape | Color | Best for |
| --- | --- | --- | --- |
| `pretty` | Rich boxes / panels | Colored on a TTY, plain when piped | Reading a result by eye at the terminal |
| `text` | One status line (change/reset) or indented sections (policy) | None | grep, awk, logs, quick diffs |
| `json` | One JSON object with stable snake_case keys | None | Scripting, `jq`, ingesting into other tools |

All three decode the result identically. The format only changes presentation, never the underlying verdict. The NTSTATUS that drives success or failure is decoded the same way regardless of format (see [NTSTATUS is always decoded](#ntstatus-is-always-decoded) below).

## pretty

`pretty` is the default and is meant for a human reading the result at a terminal. For `passwolf change` and `passwolf reset` it renders a single bordered panel whose title is `success` or `failed` and whose border is green on success or red on failure, with a right-aligned label column listing `operation`, `target`, `dc`, `method`, `status`, and any extra detail rows (`_format_pretty` in `console.py`). For `passwolf policy` it renders a boxed dashboard: a header panel, a `methods` comparison grid with colored scope and verdict cells, one detail box per scope, and a `not reached` box for any method that was denied or unavailable (`_policy_pretty` in `console.py`).

!!! tip "Color on a terminal, plain text in a pipe"
    The pretty renderer keeps its colors only when stdout is a TTY. It calls `export_text(styles=sys.stdout.isatty())`, so when you redirect or pipe the output it emits the same boxes with no ANSI escapes. That means you can capture a pretty result to a file or paste it into a ticket and it stays readable, but you should still use `text` or `json` for anything you intend to parse.

=== "passwolf change result"

    ```text
    +-------------------------- success ----------------------------+
    |      operation change                                         |
    |         target CORP/jdoe                                      |
    |             dc dc01.corp.local                                |
    |         method samr-aes                                       |
    |         status STATUS_SUCCESS (0x00000000): operation         |
    |                succeeded                                      |
    +--------------------------------------------------------------+
    ```

=== "passwolf policy result"

    ```text
    +- password policy -------+
    | jdoe on dc01.corp.local |
    +-------------------------+
     methods
    +------------------+--------+--------+---------+---------+
    | method           | scope  | status | min len | history | ...
    +------------------+--------+--------+---------+---------+
    | samr-query       | domain | ok     | 7       | 24      | ...
    | ldap-domain-head | domain | ok     | 7       | 24      | ...
    | samr-getusrpwinfo| PSO    | ok     | 14      | -       | ...
    | kpasswd          | PSO    | denied | -       | -       | ...
    +------------------+--------+--------+---------+---------+

      domain password policy
      Minimum password length (MinPasswordLength)   7
      Enforce password history (PasswordHistoryLength)   24
      Maximum password age (MaxPasswordAge)   42 days
    ```

The values above are representative, not captured from a live DC, and the boxes are drawn in ASCII here so they stay copy-safe; on a terminal the Rich renderer draws the same layout with Unicode box-drawing characters. The structure (panel title, label column, the `methods` grid, the folded units like `42 days`) is exactly what the renderer produces.

Use `pretty` when you are running a command interactively and want to read the result, especially `passwolf policy`, where the cross-method comparison grid is the whole point: it shows at a glance which channels agree on the policy and where a PSO makes a per-user oracle report a different minimum than the domain reads.

## text

`text` is the greppable format. It carries no color and is designed to be piped into `grep`, `awk`, or a log.

For `passwolf change` and `passwolf reset` it is a single status line built by `_format_text`:

```text
[ok] change CORP/jdoe via samr-aes on dc01.corp.local: STATUS_SUCCESS (0x00000000): operation succeeded
```

A failure uses the `[FAIL]` prefix and carries the decoded NTSTATUS in the same position:

```text
[FAIL] change CORP/jdoe via samr-rc4 on dc01.corp.local: STATUS_WRONG_PASSWORD (0xC000006A): the supplied old password is incorrect
```

Any extra key/value detail the operation attached is printed on following lines, indented by six spaces (`key: value`), so the first line stays a clean one-shot match.

For `passwolf policy`, `text` is a set of indented, greppable sections produced by `_policy_text`: a `[methods]` block holding the aligned comparison table, then `[domain password policy]` and `[PSO (fine-grained) effective policy]` blocks, any `[PSO object: ...]` and `[domain configured intent: GPO ...]` blocks, a `[target user]` block, and a closing `[reachability]` block listing each method and its full status.

```text
password policy for jdoe on dc01.corp.local
  [methods]
      method            scope   status  min len  history  max age (d) ...
      ----------------  ------  ------  -------  -------  ----------- ...
      samr-query        domain  ok      7        24       42          ...
      ldap-domain-head  domain  ok      7        24       42          ...
      samr-getusrpwinfo PSO     ok      14       -        -           ...
  [domain password policy]
    samr-query
      Minimum password length (MinPasswordLength): 7
      Enforce password history (PasswordHistoryLength): 24
      Maximum password age (MaxPasswordAge): 42 days
  [reachability]
      samr-query: ok
      kpasswd: denied: anonymous bind not permitted
```

Use `text` when you want to grep a result, diff two runs, or drop a one-line outcome into a log. For a single change or reset the whole verdict is on line one, so `passwolf change ... --format text | grep '^\[FAIL\]'` is a reliable failure check.

## json

`json` is the scripting format. Each command prints exactly one JSON object to stdout, indented two spaces, with no color and no surrounding prose.

For `passwolf change` and `passwolf reset` the object comes from `_format_json` and has these keys:

```json
{
  "operation": "change",
  "method": "samr-aes",
  "target": "CORP/jdoe",
  "dc": "dc01.corp.local",
  "success": true,
  "status": "0x00000000",
  "status_name": "STATUS_SUCCESS",
  "detail": "STATUS_SUCCESS (0x00000000): operation succeeded",
  "extra": {}
}
```

!!! note "Stable snake_case keys"
    The JSON keys are stable and snake_case across all tools. The single-outcome object always carries `operation`, `method`, `target`, `dc`, `success` (a real JSON boolean), `status` (the NTSTATUS as an `0x`-prefixed eight-digit uppercase hex string), `status_name` (the symbolic name), `detail` (the full decoded line), and `extra` (a flat object of any additional key/value detail). For `passwolf policy`, `_policy_json` emits `target`, `dc`, `policies`, `psos`, `gpo_policies`, `reachability`, and `user_view` when a target user was read; the policy field keys inside those arrays are the stable snake_case names (`minimum_password_length`, `enforce_password_history`, `maximum_password_age`, and so on) with no display labels and no units.

The JSON view deliberately strips the official Group Policy display labels and the folded units that the `text` and `pretty` formats show. Machine consumers get bare keys and bare values, so a maximum age of `42 days` in `pretty` is the value `42` under the key `maximum_password_age` in JSON.

A `jq` example, pinning a `passwolf change` to one method and branching on the result:

```bash
result=$(passwolf change --target-domain CORP --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!' --method samr-aes --format json)
if [ "$(echo "$result" | jq -r '.success')" = "true" ]; then
  echo "changed"
else
  echo "failed: $(echo "$result" | jq -r '.status_name')"
fi
```

Pulling one policy field out of a `passwolf policy` read:

```bash
passwolf policy --dc dc01.corp.local --target-domain corp.local --auth-as-user jdoe --auth-as-password 'Passw0rd!' --format json \
  | jq -r '.policies[] | select(.scope == "domain") | .minimum_password_length'
```

Use `json` whenever another program consumes the result. Do not parse `pretty` or `text`; the JSON object is the contract.

## NTSTATUS is always decoded

Whatever format you choose, the result decodes the NTSTATUS precisely, so distinct failure causes stay distinguishable. The decoding is in `src/passwolf/nterror.py` and is shared by every formatter. That means a wrong old password, a policy rejection, and a disabled method are three different, named outcomes, not one generic failure:

| Cause | NTSTATUS | What you see |
| --- | --- | --- |
| Wrong old password | `STATUS_WRONG_PASSWORD` (0xC000006A) | `the supplied old password is incorrect` |
| New password rejected by policy | `STATUS_PASSWORD_RESTRICTION` (0xC000006C) | `new password rejected by policy (length, complexity, history, or minimum age)` |
| Method disabled or insufficient rights | `STATUS_ACCESS_DENIED` (0xC0000022) | `access denied (insufficient rights, or this method is disabled on the DC)` |

In `text` and `pretty` this decoded line is the `status` field; in `json` it is `detail`, with the symbolic name also broken out as `status_name` and the raw code as `status`. So a script can branch on `status_name == "STATUS_WRONG_PASSWORD"` versus `STATUS_PASSWORD_RESTRICTION` without parsing English. The full status table and routing notes are in [the errors reference](../internals/errors.md).

## Related pages

- [passwolf change guide](change.md): the change tool and its method choices.
- [passwolf policy guide](policy.md): the policy read whose multi-method dashboard the formats render.
- [NTSTATUS and error reference](../internals/errors.md): every decoded status and how methods route on it.
