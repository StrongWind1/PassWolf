# Architecture

passwolf is three console tools over one shared layer cake. The tools, `passwolf change`, `passwolf reset`, and `passwolf policy`, share a model, a transport binder, the crypto, and the hand-built NDR types, but they never share operation-selection logic: a change, a reset, and a read are kept strictly apart so the security model of each is obvious at the call site. This page walks the module layout, the import boundaries that enforce that separation, the AUTO method-selection logic, and one invocation from argument to rendered outcome. Every path below is real and lives under `src/passwolf/`.

## Module layout

The package splits into a shared core, a set of per-protocol method modules, a separate read surface, the rendering layer, and three CLI entry points.

| Layer | Module | Role |
|---|---|---|
| Shared core | `model.py` | Transport-agnostic types and enums: `ChangeMethod`, `ResetMethod`, `OutputFormat`, `TransportKind`, `AccountKind`, the `Target` and `Secret` records, and the `--target-domain` / `--target-user` / `--dc` resolver. |
| Shared core | `transport.py` | The DCE/RPC channel binder: `BindIdentity` (the principal that authenticates the bind) and `open_channel`, which returns a `Channel` carrying the bound `dce` and, over SMB, the session key. |
| Shared core | `crypto.py` | The password cryptography for every wire format: DES OWF, the RC4 SAM buffers, the AEAD-AES-256-CBC-HMAC-SHA512 SAM and LSA buffers, the PBKDF2 content-encryption key, and the AES-128-CFB8 Netlogon buffer. |
| Shared core | `ndr.py` | The NDR wire structures impacket does not model, plus the dispatch and union splices that let impacket carry them. |
| Shared core | `constants.py` | Opnum numbers, info-class values, feature bits, and UAC flags, each cited to its spec section. |
| Change/reset methods | `samr.py` | The SAMR change and reset operations, and the `SamrConnect5` AES capability preflight. |
| Change/reset methods | `netlogon.py` | The Netlogon machine and trust change over the sealed secure channel (opnums 30 and 6). |
| Change/reset methods | `lsa.py` | The LSA trust-secret set (`LsarSetSecret2` opnum 138, `LsarSetSecret` opnum 29). |
| Change/reset methods | `kpasswd.py` | The Kerberos change (no targname/targrealm) and set (with targname/targrealm) protocols, both framed with protocol version 0xFF80. |
| Change/reset methods | `ldap.py` | The LDAP `unicodePwd` change (delete-old + add-new) and reset (single replace). |
| Change/reset methods | `rap.py` | The legacy RAP `NetUserPasswordSet2` change (opcode 115) and OEM change (opcode 214) over SMB1. |
| Read surface | `policy.py` | One function per policy-read wire method, importing nothing from the change/reset modules. |
| Read surface | `policymodel.py` | The normalized policy records (`PasswordPolicy`, `PsoPolicy`, `GptTmplPolicy`, `UserPolicyView`, `PolicyReadResult`) and their decoders. |
| Rendering | `console.py` | `Outcome`, `render`, and `render_policy`: the text, JSON, and pretty formatters for both the change/reset outcome and the policy read. |
| Errors | `nterror.py` | NTSTATUS decoding: symbolic name, operator-facing description, and the success test. |
| Errors | `errors.py` | The two control-flow exceptions: `MethodUnavailable` (drives AUTO fallback) and `OperationFailed` (a definite non-NTSTATUS failure). |
| Entry points | `change.py` | The `passwolf change` CLI. |
| Entry points | `reset.py` | The `passwolf reset` CLI. |
| Entry points | `pwpolicy.py` | The `passwolf policy` CLI. |

!!! note "The netlogon module"
    The machine and trust change lives in `netlogon.py`. It binds the Netlogon RPC interface (NRPC) directly rather than going through `transport.open_channel`, because the secure channel has its own `NetrServerReqChallenge` + `NetrServerAuthenticate3` handshake and must be upgraded to `RPC_C_AUTHN_NETLOGON` sign+seal before the write. See [transport](transport.md) for why it sits outside the shared channel binder.

## Import DAG

The dependency graph is a DAG with the shared core at the bottom and the three entry points at the top. Nothing in the core imports a method module, and no method module imports an entry point.

```
model.py   constants.py        (no intra-package imports)
   |            |
crypto.py ------+               (crypto -> constants)
   |            |
ndr.py --------/                (ndr -> constants)
   |
samr / netlogon / lsa / kpasswd / ldap / rap   ->  crypto, ndr, constants, errors, nterror, model
   |
change.py  reset.py            ->  the change/reset method modules + console + transport + model + nterror + errors

policy.py            ->  crypto, ndr, constants, policymodel        (imports NO change/reset module)
policymodel.py       ->  (standalone records)
pwpolicy.py          ->  policy, policymodel, console, transport, model, errors
```

`console.py` depends only on `nterror`, `model`, and (lazily, inside the pretty formatter) `rich` and `policymodel`. It is imported by all three entry points and imports none of them.

## The change / reset / read boundary

The split between the three operations is not a convention, it is an import boundary.

=== "Change vs reset"

    The change-versus-reset distinction is encoded as two separate enums in `model.py`, `ChangeMethod` and `ResetMethod`, that never overlap. A change carries an old-secret proof on the wire; a reset is a privileged overwrite that proves nothing. The two CLIs build different immutable configs (`ChangeConfig` in `change.py`, `ResetConfig` in `reset.py`) and dispatch through different functions (`_run_change` vs `_run_reset`). They share `samr.py`, but `samr.py` exposes change entry points (`change_aes`, `change_rc4`, ...) and reset entry points (`reset_aes`, `reset_rc4`, `reset_hash`, ...) as distinct functions, so a reset code path can never accidentally send a change.

=== "Read vs change/reset"

    The policy read is a third operation with no path that can mutate a secret. `policy.py` reuses `crypto.py` and `ndr.py` but imports nothing from any change/reset module. The read vocabulary is deliberately kept out of `model.py`: the policy method identifiers are plain string constants local to `pwpolicy.py` (`SAMR_QUERY`, `LDAP_DOMAIN`, `SYSVOL`, ...), and the normalized records live in `policymodel.py`, which the module docstring describes as kept apart from `model.py` "so the read vocabulary never mixes with the change/reset model." Even the methods that probe a change-failure path (the opnum-63 oracle, the kpasswd SOFTERROR probe) read only: they prove identity and harvest the returned policy without ever applying a change.

!!! warning "Why this matters"
    Conflating change and reset is the root cause of the bundled `changepasswd.py` confusion where a wrong-old-password change is indistinguishable from a policy block, and where a self-change blocked by minimum age looks like a permission error. Keeping the operations apart as separate tools, separate enums, and separate dispatch makes the required privilege and the policy-bypass semantics explicit. See [Choosing a method](../guide/choosing-a-method.md) for the user-facing version of this split.

## AUTO method selection

Both `passwolf change` and `passwolf reset` default to `--method auto`, but the two AUTOs differ. `passwolf change` AUTO stays within the SAMR change and falls back only when a method is genuinely unavailable (the opnum faulted out of range, the transport cannot carry the method, or a required input is missing), signalled by a `MethodUnavailable` exception, not an NTSTATUS rejection. `passwolf reset` AUTO is a cross-protocol ladder: it tries kpasswd, then ldaps (636), then ldap (389), then the SAMR rungs (samr-aes, samr-rc4, samr-rc4-unsalted, samr-hash), taking the first that returns `STATUS_SUCCESS`. Because the rungs span protocols with different rights and policy semantics, a `passwolf reset` rung is abandoned on *any* failure (an unavailable method or a non-success NTSTATUS alike) and the next is tried; samr-hash is the last resort, applying even when a password policy rejected every cleartext rung.

### The AES vs RC4 preflight

The AES-vs-RC4 decision is made deterministically, not by guessing from OS build numbers. `samr.supports_aes` issues a `SamrConnect5` (opnum 64) and reads the `SupportedFeatures` field. It returns `True` when the server advertises the AES feature bit (0x10, per [MS-SAMR] 2.2.7.15 / 3.2.2.4), `False` when it explicitly does not, and `None` when `SamrConnect5` is unavailable (pre-Vista) or the response cannot be read.

=== "AUTO change"

    `_auto_samr_change` in `change.py`:

    1. Call `samr.supports_aes`. If it returns `False`, go straight to the RC4 change (`SamrUnicodeChangePasswordUser2`, opnum 55).
    2. Otherwise try the AES change (`SamrUnicodeChangePasswordUser4`, opnum 73).
    3. Keep the fault fallback as a safety net: if the AES attempt raises `MethodUnavailable`, or returns `STATUS_NOT_SUPPORTED` (0xC00000BB), fall back to the RC4 change.
    4. For machine and trust accounts, `_auto_machine_change` runs a separate ladder: `NETLOGON_AES` (opnum 30) first; then, for a *machine* account only, the SAMR AES cleartext change (`SAMR_AES`), which hands the DC the plaintext so it regenerates every Kerberos key; then `NETLOGON_DES` (opnum 6) as the floor. A trust account skips the SAMR rung (it is not SAMR-changeable that way), so its ladder is `NETLOGON_AES` -> `NETLOGON_DES`. Each rung yields to the next on `MethodUnavailable`.

=== "AUTO reset"

    `_run_auto_reset` (and its SAMR tail `_auto_samr_ladder`) in `reset.py` walk a cross-protocol ladder, taking the first rung that returns `STATUS_SUCCESS`:

    1. If the operator supplied only a new NT hash rather than a cleartext password, AUTO skips every cleartext rung and goes straight to the set-hash reset (`SAMR_HASH`, `UserInternal1` level 18, opnum 37, the identical sibling of SamrSetInformationUser2 opnum 58), because that is the only rung that can write a raw hash. `UserAllInformation` (level 21) can also carry the NT/LM OWF fields, so the dedicated `UserInternal1` class is a deliberate choice rather than a wire necessity. See [reset methods](reset-methods.md) for the op37/op58 equivalence.
    2. For a cleartext new password, try **kpasswd** (Kerberos set), then **ldaps** (636), then **ldap** (389). Each is abandoned on any failure (a closed port, an auth error, or a non-success status) and the next is tried.
    3. Open one SAMR named-pipe channel and call `samr.supports_aes`. Try **samr-aes** (`UserInternal7`) unless the preflight returned `False`, then **samr-rc4** (`UserInternal4InformationNew`), then **samr-rc4-unsalted** (`UserInternal4Information`).
    4. Fall back last to **samr-hash** (`UserInternal1`), which writes the NT OWF derived from the cleartext and so still applies when a password policy rejected every cleartext rung. If even this fails, AUTO raises `MethodUnavailable` with the accumulated per-rung reasons.

!!! tip "Pinning a method disables fallback"
    When `--method` names a concrete method instead of `auto`, AUTO is skipped entirely and that method runs once. A pinned method that the DC rejects reports the real error rather than silently trying another, which is what you want when you are testing whether a specific opcode is enabled. The full method names are in [change methods](change-methods.md) and [reset methods](reset-methods.md), and the opnum-to-spec mapping is in the [method matrix](../methods.md).

## One invocation, end to end

A `passwolf change` run flows through six stages. The other two tools follow the same shape with their own config and dispatch.

1. **Parse arguments.** `change.main` builds the argument parser and parses `argv`. The target is taken from `--target-domain`, `--target-user`, and `--dc` (with `--dc` defaulting to `--target-domain`) and assembled by `model.parse_target`, and any `--target-old-hash` is decoded by `model.parse_hash_pair` into raw LM/NT bytes.

2. **Build the immutable config.** `_build_config` resolves the parsed namespace into a frozen `ChangeConfig`: the `Target`, the new password, the old `Secret` (cleartext or NT hash), the `AccountKind`, the selected `ChangeMethod`, the `TransportKind`, the `BindIdentity` for the RPC bind, the NetBIOS name for the Netlogon channel, the LDAPS flag, and the `OutputFormat`. The config is `@dataclass(frozen=True)`, so nothing downstream can mutate the resolved request. Missing inputs raise `ValueError` here and exit with status 2.

3. **Open the channel.** For the SAMR methods, `_run_samr_change` calls `transport.open_channel` with the SAMR interface UUID, the `\samr` pipe, and the chosen transport. Over SMB the SMB session key is captured into the `Channel` (the reset cleartext info levels need it as their content-encryption key); over TCP there is no session key. The Kerberos, LDAP, RAP, and Netlogon methods open their own transport inside their modules rather than through the shared binder.

4. **Run the selected (or AUTO-selected) method.** `_run_change` dispatches by account kind first (machine and trust go to `_run_netlogon_change`), then by method. SAMR methods go through `_run_samr_change`, which either runs the pinned method once or runs `_auto_samr_change`. The method function builds its wire structure (from `ndr.py` for the AES and undocumented paths), encrypts the buffer (`crypto.py`), sends the request, and returns the raw NTSTATUS as an `int`.

5. **Decode the NTSTATUS.** The returned status, method name, target label, and DC are packed into a single `console.Outcome`. `Outcome.success` calls `nterror.is_success`, and the formatters call `nterror.describe` to turn the code into an operator-facing line, distinguishing a wrong old password (`STATUS_WRONG_PASSWORD`) from a policy rejection (`STATUS_PASSWORD_RESTRICTION`) from a disabled method (`STATUS_ACCESS_DENIED`). See [errors and NTSTATUS](errors.md).

6. **Render the outcome.** `console.render(outcome, cfg.output)` selects the formatter for the chosen `OutputFormat`. The default is **pretty**: a `rich` panel, green on success and red on failure, with `rich` imported lazily only inside that formatter so the text and JSON paths carry no import cost. `text` is a single greppable status line; `json` is one object. The process exits 0 on `STATUS_SUCCESS`, 1 on a failed or unavailable method, and 2 on a usage error.

??? note "Where MethodUnavailable and OperationFailed surface"
    `MethodUnavailable` is caught both inside AUTO (to trigger fallback) and at the top of `main` (an unavailable pinned method exits 1 with a clear log line). `OperationFailed`, raised by the non-NTSTATUS protocols (Kerberos kpasswd and LDAP) when they report a definite failure, is turned into a failed `Outcome` carrying the protocol's own detail string, so the result still renders in the chosen format rather than crashing. A raw `DCERPCException` that escapes a method is logged and exits 1.

The output formats themselves, including the default change to pretty, are covered in [Output formats](../guide/output-formats.md). The cryptographic constructions each method uses are in [crypto and password buffers](crypto.md), and the per-method wire detail is in [change methods](change-methods.md), [reset methods](reset-methods.md), and [policy read methods](policy-methods.md).
