# Errors and NTSTATUS

Every SAMR and Netlogon password operation reports its outcome as an NTSTATUS in the RPC response. passwolf decodes that code precisely, because the difference between a wrong old password, a policy rejection, and a method the DC has disabled is the whole signal an operator needs, and impacket collapses several distinct codes into one generic string. This page covers the decode table in `nterror.py`, the `call()`/`recv()` versus `request()` distinction that keeps the diagnostics body intact, the cross-encryption retry, the two exception types in `errors.py`, and the `ok` / `denied` / `unavailable` / `failed` / `skipped` reachability map that passwolf policy builds.

## Success versus failure

`nterror.is_success(status)` masks the value to 32 bits and compares it against `STATUS_SUCCESS` (`0x00000000`). Nothing else counts as success: a code is success only when it is exactly zero.

The console layer reads this through the `Outcome` dataclass. `Outcome.success` calls `nterror.is_success(self.status)`, `Outcome.status_name` calls `nterror.name(self.status)`, and the renderer formats the full line with `nterror.describe(self.status)`. The process exit code follows directly: passwolf change returns `0` when `outcome.success` is true and `1` otherwise.

```python
def is_success(status: int) -> bool:
    """Return whether an NTSTATUS code indicates success."""
    return (status & 0xFFFFFFFF) == STATUS_SUCCESS
```

## Symbolic names and descriptions

`nterror.py` keeps one table, `_NAMES`, mapping each known code to a `(symbolic_name, operator_meaning)` pair. Three functions read it:

| Function | Returns | On an unmapped code |
| --- | --- | --- |
| `name(status)` | the symbolic name, for example `STATUS_WRONG_PASSWORD` | the hex form `0x{code:08X}` |
| `describe(status)` | `NAME (0xCODE): meaning` | `unmapped NTSTATUS 0x{code:08X}` |
| `is_success(status)` | `True` only for `STATUS_SUCCESS` | `False` |

Every code is masked with `& 0xFFFFFFFF` before lookup, so a sign-extended or wider integer from impacket still resolves.

## Common codes a caller will see

These are the codes the decode table exists to separate. The meanings are operator-facing and call out the routing behavior, not just the literal name.

| Code | Name | Meaning |
| --- | --- | --- |
| `0x00000000` | `STATUS_SUCCESS` | operation succeeded |
| `0xC000006A` | `STATUS_WRONG_PASSWORD` | the supplied old password is incorrect |
| `0xC000006C` | `STATUS_PASSWORD_RESTRICTION` | new password rejected by policy (length, complexity, history, or minimum age) |
| `0xC000006B` | `STATUS_ILL_FORMED_PASSWORD` | the new password is malformed |
| `0xC0000022` | `STATUS_ACCESS_DENIED` | access denied (insufficient rights, or this method is disabled on the DC) |
| `0xC00000BB` | `STATUS_NOT_SUPPORTED` | this method is not supported on the DC |
| `0xC000015D` | `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` | the server needs the new NT hash cross-encrypted with the new LM hash (opnum 38 retry) |
| `0xC000017F` | `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` | the server needs the new LM hash cross-encrypted with the new NT hash (opnum 38 retry) |
| `0xC0000064` | `STATUS_NO_SUCH_USER` | no such user (or wrong account type for this method) |
| `0xC000000D` | `STATUS_INVALID_PARAMETER` | the server rejected the request structure |

The table also carries `STATUS_UNSUCCESSFUL` (`0xC0000001`, the generic stand-in for non-NTSTATUS protocols), `STATUS_PASSWORD_EXPIRED`, `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_EXPIRED`, `STATUS_ACCOUNT_LOCKED_OUT`, and `STATUS_TRUSTED_DOMAIN_FAILURE`.

!!! warning "STATUS_ACCESS_DENIED is overloaded"
    On a modern DC, `STATUS_ACCESS_DENIED` from a legacy SAMR or opnum-63 path is not always a per-user permission problem. Server 2025 gates the legacy RC4 change (the CVE-2021-33757 mitigation), so the same code there means "this method is disabled," which is why its description names both cases. The opnum-63 oracle treats this code as a signal to give up on that channel and use kpasswd instead. See [change-methods.md](change-methods.md) for how the change paths react to it.

## call()/recv() versus request(): keeping the diagnostics

impacket's `DCERPC_v5.request()` deserializes the response and raises a `DCERPCSessionError` if the trailing NTSTATUS is non-zero, before the caller can read anything else in the body. For most operations that is fine: the status is the entire result. Two paths need more than the status, and for them the auto-raise would throw away exactly the data being read.

The opnum-63 change, `SamrUnicodeChangePasswordUser3`, returns a structured failure body alongside a non-zero `ErrorCode`. On a policy rejection the server fills `EffectivePasswordPolicy` (the effective `DOMAIN_PASSWORD_INFORMATION`: minimum length, history depth, minimum age) and `PasswordChangeInfo` (the `USER_PWD_CHANGE_FAILURE_INFORMATION` extended reason), then sets `ErrorCode` to something like `STATUS_PASSWORD_RESTRICTION`. If `request()` raised on that code, the policy block would never be read.

So both the passwolf change diagnostic change (`samr.change_diag`) and the passwolf policy opnum-63 oracle (`policy.samr_oracle_policy`) issue the call by hand:

```python
try:
    dce.call(request.opnum, request)
    stub = dce.recv()
except DCERPCException as exc:
    raise MethodUnavailable(str(exc)) from exc
response = ndr.SamrUnicodeChangePasswordUser3Response(stub)
```

`call()` sends the request and `recv()` takes the raw stub back without inspecting the trailing status, so the body is parsed by hand from `stub`. A genuine RPC fault (the opnum being unsupported, for instance) still raises out of `call()`/`recv()` as a `DCERPCException`, and that is caught and re-raised as `MethodUnavailable`. A non-zero NTSTATUS in the body is not a fault and does not raise; it is read off the deserialized response as `ErrorCode`.

??? note "How the diagnostics body is read"
    impacket auto-dereferences a populated `[unique]` referent into the struct directly and a null referent into empty `bytes`. The code uses that: `if not isinstance(policy, bytes)` is the test for "the server filled this block." The server only fills both out-structs on a `STATUS_PASSWORD_RESTRICTION`, so on any other status the diagnostics are simply absent, and the extra map stays empty. The minimum-age field is an `OLD_LARGE_INTEGER` of negative 100-nanosecond ticks; it is reported as a magnitude in days. The extended reason codes are `1` too-short, `2` in-history, `5` not-complex, and `0` minimum-age.

The rest of the change methods (AES opnum 73, OEM opnum 54, the DES opnum-38 change, and the resets) carry no diagnostics body, so they go through the `_request_status` helper, which uses `request()` and converts a `DCERPCSessionError` into its status code and a generic `DCERPCException` into `MethodUnavailable`. The legacy RC4 change (opnum 55) is the one exception: it goes through impacket's `hSamrUnicodeChangePasswordUser2` helper (which calls `request()` internally) with the same `DCERPCSessionError` -> status / `DCERPCException` -> `MethodUnavailable` mapping written out inline rather than via `_request_status`.

## The cross-encryption retry

`SamrChangePasswordUser` (opnum 38, the DES OWF change) has a retry built on two specific status codes. When an account stores only one of its two hashes (only NT, or only LM), the server authenticates on the hash it has and then asks for the missing new hash cross-encrypted under the other, returning `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` (`0xC000015D`) or `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` (`0xC000017F`). This is per [MS-SAMR] 3.1.5.10.1.

`samr.change_des` sends the request without cross-encryption first, then loops at most twice:

- On `STATUS_NT_CROSS_ENCRYPTION_REQUIRED` it sets `nt_cross` and resends with `NewNtEncryptedWithNewLm` populated.
- On `STATUS_LM_CROSS_ENCRYPTION_REQUIRED` it sets `lm_cross` and resends with `NewLmEncryptedWithNewNt` populated.
- On any other status it stops and returns that status.

An account is missing at most one stored hash, so at most one cross round is ever needed; the loop bound of two leaves room for the resend and the terminal read. Each attempt builds a fresh request struct, because an impacket NDRCALL does not re-serialize cleanly after a referent field is flipped from NULL to a pointer. The two cross-encryption status codes are therefore transient control signals inside `change_des`, not failures the caller sees; only the final status leaves the function.

## Distinguishing the three failure shapes

For a user change, the three outcomes an operator most needs to tell apart all come back as plain NTSTATUS values and are separated entirely by the decode table:

=== "Wrong old password"

    `STATUS_WRONG_PASSWORD` (`0xC000006A`). The credential proving the change is wrong. The console line reads `the supplied old password is incorrect`. No `extra` detail is attached.

=== "Policy rejection"

    `STATUS_PASSWORD_RESTRICTION` (`0xC000006C`). The new password violates length, complexity, history, or minimum age. Over the ordinary AES or RC4 change this is the bare status. Over the opnum-63 diagnostic change (`--method samr-diag`) the `extra` map also carries `min_password_length`, `password_history_length`, `min_password_age_days`, and `change_failure_reason`, so the operator sees the actual policy that rejected the password rather than only that something did.

=== "Disabled method"

    `STATUS_NOT_SUPPORTED` (`0xC00000BB`) or `STATUS_ACCESS_DENIED` (`0xC0000022`). The DC will not carry this method at all. In AUTO mode the AES change returning `STATUS_NOT_SUPPORTED` triggers the fallback to the RC4 change rather than reporting a failure; a pinned method reports the status as-is.

## MethodUnavailable versus OperationFailed

`errors.py` defines two exception types under a `PasswolfError` base, and the distinction drives both AUTO fallback and the policy reachability map.

`MethodUnavailable` means the method could not be evaluated by the server at all: the RPC opnum faulted out of range, the transport cannot carry the method, or a required input is missing. It is explicitly not an NTSTATUS result. Because it means "the server never judged the request," AUTO is free to fall back to another method when it sees it. The SAMR helpers raise it on a generic `DCERPCException`, and the AES-to-RC4 fallback in `_auto_samr_change` catches it directly.

`OperationFailed` means a non-NTSTATUS protocol, Kerberos kpasswd or LDAP, reported a definite failure. These protocols return their own result codes instead of an NTSTATUS, so the carried message is the authoritative detail. In passwolf change, an `OperationFailed` becomes an `Outcome` with `STATUS_UNSUCCESSFUL` and the message placed in `extra["detail"]`, so it renders through the same status line as everything else.

!!! note "Why two types and not one"
    The split exists so AUTO can distinguish "try the next method" from "this method ran and definitively failed." `MethodUnavailable` is recoverable by falling back; `OperationFailed` is a real verdict from a protocol that does not speak NTSTATUS.

## The passwolf policy reachability map

passwolf policy runs every selected read method independently and records a verdict for each in `result.reachability`. It never collapses to one answer: an anonymous probe shows exactly which channels leak the policy and which deny it. The exit code is `0` when at least one method's verdict is `ok` and `1` when every method was denied, unavailable, failed, or skipped.

Each method runs through `_attempt`, which records one of five verdict prefixes:

| Verdict | Source | Meaning |
| --- | --- | --- |
| `ok` | the method returned without raising | the read succeeded and its policy data was recorded |
| `denied` | `_classify` matched an access-denied signal | the DC refused this principal on this channel |
| `unavailable: <text>` | `_classify` on any other wire error | the channel could not carry the read |
| `failed: <text>` | `OperationFailed` | a non-NTSTATUS protocol reported a definite failure |
| `skipped: <reason>` | `_skip`, before the run | a precondition was unmet, so the method was not attempted |

`_classify` distinguishes denial from absence by inspecting the exception text: it returns `denied` when the message contains `access_denied`, `access denied`, `0x00000005`, or `insufficientaccessrights`, and otherwise returns `unavailable:` followed by the message. `MethodUnavailable`, `DCERPCException`, `LDAPSessionError`, `SessionError`, and `OSError` all flow through `_classify`; only `OperationFailed` becomes `failed`.

Skips are recorded before any wire traffic, so they read as preconditions rather than failures:

- The per-user methods (`samr-getusrpwinfo`, `ldap-resultant`, `ldap-uac`) are skipped with `no --target-user` when no target account is named.
- The change-failure oracles (`samr-diag`, `kpasswd`) are skipped with `needs authentication` on an anonymous bind, since they prove identity as the authenticating principal.

The pretty dashboard (the default output, see below) tints each verdict: `ok` green, `denied` / `unavailable` / `failed` red, and `skipped` yellow, so the reachability of every channel is scannable at a glance. For how the opnum-63 oracle, the kpasswd oracle, and the LDAP and SYSVOL reads each produce their policy rows, see [policy-methods.md](policy-methods.md).

## Output format

The default output format is `pretty` for all three tools, which changed recently from `text`. `pretty` renders a boxed Rich panel (a single-status panel for passwolf change and passwolf reset, the methods-and-reachability dashboard for passwolf policy). `text` emits the greppable single-line status form, and `json` emits a structured object whose `status` field is the masked hex code, `status_name` is the symbolic name, and `detail` is the `describe()` string. The verdict in every format comes from the same `is_success` and `describe` calls discussed above. See [../guide/output-formats.md](../guide/output-formats.md) for the full rendering of each format.
