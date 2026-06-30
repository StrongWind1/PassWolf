# passwolf change: change a password

`passwolf change` changes the password of an Active Directory account by proving that account's current secret. It is a change, not a reset: you supply either the current cleartext password or its current NT hash, and the directory verifies that secret before it accepts the new one. Because the operation proves knowledge of the existing credential, it needs no privilege on the target. An ordinary user can change their own password with it.

A change is subject to the full domain password policy. Minimum length, complexity, the password history count, and the minimum password age all apply, exactly as they do when a user changes their password at the Windows logon screen. If the new password fails any of these, the DC rejects the change and `passwolf change` reports the failure. If you need to overwrite a password without proving the old one and without satisfying minimum age or history, that is a reset, which requires privilege and is the job of [passwolf reset](reset.md).

!!! note "Change versus reset in one sentence"
    A change proves the old secret and is bound by the full policy. A reset overwrites the secret with privilege and skips minimum age and history. See [Choosing a method](choosing-a-method.md) for which one fits your situation.

## What it does

`passwolf change` sends a Windows password-change request to the DC over whichever protocol the chosen method uses: SAMR, the Kerberos change protocol, LDAP, the Netlogon secure channel, or the legacy RAP path. The new password is carried in an encrypted buffer keyed by the old secret, so the change verifies the old credential as a side effect of decrypting the buffer. For wire-level detail on each method, see [Change methods](../internals/change-methods.md).

The default method, `auto`, selects the strongest change the DC will accept and falls back only when a method is genuinely unavailable. On Windows Server 2025 the AES SAMR change is the only SAMR change that succeeds once the legacy RC4 changes are disabled, and `auto` selects it there automatically.

## The target

The `--target-user`, `--target-domain`, and `--dc` flags name the account to change and the DC to reach:

```
passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
```

`jdoe` is the account whose password changes, `dc01.corp.local` is the domain controller that processes the request, and `corp.local` is the DNS domain. Both `--target-user` and `--target-domain` are required. `--dc` is optional and defaults to the `--target-domain` value when omitted.

## Options

### `--target-new-password PASS` and `--target-new-hash [LM:]NT` (required: give one)

The new secret to set: give a password or a hash. Supply exactly one of these two flags.

- `--target-new-password PASS` is the new cleartext password. It is effectively required, but you do not have to put it on the command line: omit it and `passwolf change` prompts for it on the terminal without echoing what you type. The value must satisfy the domain password policy; if it does not, the DC rejects the change.
- `--target-new-hash [LM:]NT` sets the new password directly from a raw NT hash, with no cleartext anywhere. You may prefix the LM hash with a colon, as `LM:NT`, or pass the NT hash alone. It is mutually exclusive with `--target-new-password`.

### `--target-new-hash [LM:]NT` in detail

`--target-new-hash` writes the account's new password as a raw NT one-way function, bypassing cleartext entirely. It works only through the DES change (`SamrChangePasswordUser`, opnum 38), so it automatically pins `--method samr-des`. Passing `--target-new-hash` together with a different explicit `--method`, such as `--method samr-rc4`, is a usage error and exits `2`.

It still proves the old secret, through `--target-old-password` or `--target-old-hash`, exactly like any other change. That proof is what makes it need no privilege on the target, and it is what distinguishes it from [`passwolf reset --target-new-hash`](reset.md), which overwrites the hash with reset rights and proves nothing.

Because it writes the NT OWF directly, the side effects are unavoidable and worth stating plainly:

- It bypasses password complexity, length, and history. The DC never sees a cleartext to evaluate against the policy.
- It drops the account's Kerberos keys until the next real (cleartext) password change, because there is no cleartext from which to derive AES and DES keys.
- It flags the password as expired, so the account must change its password at the next logon.
- It is NT-only. The new LM cross-encryption uses the supplied LM half when you give one, or the empty-LM placeholder otherwise.

One legacy edge: an account that still stores an LM hash, which is rare on a modern DC running with `NoLMHash` set, can reject the change with `STATUS_LM_CROSS_ENCRYPTION_REQUIRED`.

!!! note "Expired and must-change accounts change over a null session"
    When the target account's password is already expired, or flagged "must change at next logon", the authenticated SAMR bind fails. `passwolf change` then retries the bind over a NULL SESSION and sends the change that way. This is exactly how an expired password is meant to be changed: the buffer-based changes carry the old-secret proof inside the request, so no authenticated session is required ([MS-SAMR] 3.1.5.10.3). This path works only for the buffer-based methods, `samr-aes`, `samr-rc4`, `samr-oem`, `samr-diag`, and `auto`. The handle-based `samr-des` change needs a user handle that a null session is denied, so an expired account combined with `samr-des` reports a clear "unavailable" message.

### `--target-old-password PASS` and `--target-old-hash [LM:]NT` (required: give one, or be prompted)

The current credential that proves the change. Supply exactly one of these, or supply neither and `passwolf change` prompts for the current password on the terminal without echo. The one exception is the `ldap` change, which can run without proving the old secret, so it does not prompt.

- `--target-old-password PASS` is the account's current cleartext password.
- `--target-old-hash [LM:]NT` is the account's current NT hash, for a pass-the-hash change. You may prefix the LM hash with a colon, as `LM:NT`, or pass the NT hash alone.

Prompting for the secret instead of taking it on the command line keeps it off the process list, where other local users could otherwise read it.

!!! tip "Pass-the-hash without the cleartext"
    Use `--target-old-hash` when you hold the NT hash but not the password. The SAMR RC4 and AES changes both derive their encryption key from the old NT hash, so a hash is sufficient to prove the change. Pin the method to `samr-aes` or `samr-rc4` when changing by hash, because `kpasswd` and `ldap` need the cleartext old password.

The `ldap` change, like `kpasswd`, needs the cleartext old password: the delete-old half of the `unicodePwd` Modify is built from the old password and is sent on the wire as the delete value, so `--target-old-hash` cannot drive it. Every method needs `--target-old-password` or `--target-old-hash`, and `kpasswd` and `ldap` specifically require `--target-old-password`.

### `--target-domain DNS` (required)

The DNS domain. Required, like `--target-user`. It also supplies the default for `--dc` when that flag is omitted, and the default for `--auth-as-domain`.

```
passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
```

### `--account {user,machine,trust}` (optional)

The kind of account being changed. Optional; the default is `user`.

- `user` is an ordinary domain user account, changed over SAMR, Kerberos, or LDAP.
- `machine` is a computer account secret, changed over the Netlogon secure channel.
- `trust` is an interdomain trust account secret, also changed over Netlogon.

When the account kind is `machine` or `trust`, `passwolf change` ignores the SAMR and Kerberos methods and uses the Netlogon channel: `NetrServerPasswordSet2` (opnum 30) for the AES buffer and `NetrServerPasswordSet` (opnum 6) for the DES one. The machine account name ends in `$`, so quote it in shells that treat `$` specially, as `--target-user 'WS01$'`.

### `--method METHOD` (optional)

The change method, or `auto` (the default). Optional. The full list:

| Method | Protocol and operation | Notes |
|---|---|---|
| `auto` | picks the strongest method the DC accepts | preflights for AES, falls back to RC4 only when needed |
| `samr-aes` | `SamrUnicodeChangePasswordUser4`, opnum 73 | AES password buffer; the only SAMR change Server 2025 accepts |
| `samr-rc4` | `SamrUnicodeChangePasswordUser2`, opnum 55 | legacy RC4 buffer keyed by the old NT hash |
| `samr-oem` | `SamrOemChangePasswordUser2`, opnum 54 | RC4 buffer keyed by the old LM hash, OEM charset |
| `samr-des` | `SamrChangePasswordUser`, opnum 38 | DES cross-encryption, opens a user handle first; the only method `--target-new-hash` can use |
| `samr-diag` | `SamrUnicodeChangePasswordUser3`, opnum 63 | undocumented diagnostic change, returns policy detail |
| `kpasswd` | Kerberos change protocol, framed with version `0xFF80`, no targname/targrealm | needs the cleartext old password |
| `ldap` | LDAP `unicodePwd` delete-old plus add-new | runs over sealed LDAP on 389, or LDAPS with `--ldaps` |
| `netlogon-aes` | `NetrServerPasswordSet2`, opnum 30 | machine and trust accounts, AES buffer |
| `netlogon-des` | `NetrServerPasswordSet`, opnum 6 | machine and trust accounts, DES OWF |
| `rap` | RAP `NetUserPasswordSet2`, opcode 115 | legacy cleartext over SMB1 `\PIPE\LANMAN`, Server 2008 and earlier |
| `rap-oem` | RAP `SamOEMChangePasswordUser2`, opcode 214 | legacy RC4 OEM over SMB1, Server 2008 and earlier |

!!! danger "The RAP methods reach only legacy targets"
    `rap` and `rap-oem` ride SMB1 over `\PIPE\LANMAN` and reach only Server 2008 and earlier. `auto` never selects them. They differ in both wire exposure and what they store: `rap` (opcode 115) sends the password in cleartext and is LM-only (the gateway never writes the NT hash, so the result is not NTLM-usable), while `rap-oem` (opcode 214) carries an RC4 OEM buffer keyed by the old LM hash and is not LM-only -- the server recomputes and stores a real NT (and LM) hash from the decrypted OEM cleartext, so its result is NTLM-usable (live-confirmed by secretsdump). Both complete on NT 4.0; prefer `rap-oem` because plain `rap` requires the password to be OEM-uppercased (a mixed-case password fails the LM old-password verifier with `ERROR_INVALID_PASSWORD`) while `rap-oem` carries an RC4 buffer and needs no such handling. Plain `rap` is a no-op only on Server 2003/2008 and XP. Do not use either against a modern DC.

??? note "How AUTO chooses for a user account"
    `auto` runs a `SamrConnect5` SupportedFeatures preflight to learn whether the DC wants the AES password buffer (feature bit `0x10`, [MS-SAMR] 2.2.7.15). When the DC advertises AES, `auto` uses the AES change at opnum 73. When the DC explicitly does not advertise it, `auto` goes straight to the RC4 change at opnum 55. If the preflight is unavailable, on servers too old to expose `SamrConnect5`, `auto` tries AES first and drops to RC4 only on a genuine `STATUS_NOT_SUPPORTED` or unavailability fault, never merely for compatibility. For a machine or trust account, `auto` tries the Netlogon AES change first. A machine account then falls back to the SAMR AES cleartext change (a computer is a user-class object, and the cleartext lets the DC regenerate every Kerberos key) before the legacy Netlogon DES OWF; a trust account, which is not SAMR-changeable that way, falls straight from Netlogon AES to Netlogon DES. This logic lives in `src/passwolf/change.py`.

### `--transport {smb,tcp}` (optional)

The transport for the SAMR change. Optional; the default is `smb`, which reaches SAMR over the `\pipe\samr` named pipe on top of SMB. `tcp` reaches the same interface over a direct ncacn_ip_tcp endpoint instead. This option affects the SAMR methods only; `kpasswd`, `ldap`, the Netlogon methods, and the RAP methods carry their own transport. See [Transport](../internals/transport.md).

### `--auth-as-user USER` (optional)

Bind the SAMR or LDAP session as a different principal than the account being changed. This and its companion flags are optional. By default `passwolf change` binds as the target account using the old credential. With `--auth-as-user` you authenticate the channel as one principal while changing the password of another, which matters when the bound identity and the change buffer differ. Supply `--auth-as-user USER` alone and, if you give neither `--auth-as-password` nor `--auth-as-hash`, `passwolf change` prompts for that account's password on the terminal without echo; add `--auth-as-password PASS` to pass the password directly, or `--auth-as-hash` to bind with an NT hash. `--auth-as-domain` sets the bound principal's domain and defaults to the `--target-domain` value when omitted. This affects the SAMR and LDAP methods only.

### `-k`, `--kerberos` (optional)

Authenticate the bind with Kerberos instead of NTLM. Optional. The bind is the principal that authenticates the SAMR or LDAP session: with `--auth-as-user` given, `-k` binds that principal with Kerberos; with no `--auth-as-user` the bind is the target account itself, and `-k` binds it with Kerberos. If the `KRB5CCNAME` environment variable points to a usable ticket cache, the TGT in it is used and you can run with no password at all, so `-k` suppresses the interactive prompt for the bind password. Otherwise a TGT is requested from the KDC, which is the `--dc` host, using the supplied password or NT hash; you may still pass `--auth-as-password` or `--auth-as-hash` with `-k` to fetch a fresh ticket. `-k` governs only how the session binds. It does not touch the change proof or the new value: `--target-old-password`/`--target-old-hash` and `--target-new-password`/`--target-new-hash` are unaffected and behave exactly as before.

### `--netbios NAME` (optional)

The NetBIOS domain name for the Netlogon secure channel. Optional, and used by the `machine` and `trust` account changes. When omitted, `passwolf change` derives it from the DNS domain by taking the first label and upper-casing it, so `corp.local` becomes `CORP`. Set it explicitly when the NetBIOS name differs from the first DNS label.

### `--ldaps` (optional)

Use LDAPS on port 636 for the `ldap` method instead of sealed LDAP on port 389. Optional. By default the `ldap` change runs over a sealed (signed and encrypted) connection on 389, which protects the password without a certificate. Use `--ldaps` when the DC requires LDAPS or when you want the change to ride TLS on 636.

### `--format {text,json,pretty}` (optional)

The output format. Optional; the default is `pretty`, a colorized human-readable rendering of the outcome. `text` is a plain single-line result, and `json` is a machine-readable object for scripting. The default changed recently to `pretty`; pass `--format json` when piping into another tool. See [Output formats](output-formats.md).

### `-v`, `--verbose` (optional)

Enable debug logging. Optional. This prints the method selection decisions, the preflight result, and any fallback steps to stderr, which is the fastest way to see why `auto` chose the method it did.

## Examples

=== "Self-change (AUTO)"

    Change your own password and let `auto` pick the strongest method the DC accepts:

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!'
    ```

    On a modern DC this lands on the AES SAMR change at opnum 73. On Server 2025 it is the only SAMR change that succeeds, and `auto` selects it without any extra flag.

=== "Pass-the-hash, pinned to samr-aes"

    Change by NT hash without the cleartext old password, pinned to the AES SAMR change:

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-hash 47c4cc3a368a4a0fa79a7bf059b7adba --target-new-password 'NewPass1!' --method samr-aes
    ```

    The AES change derives its key from the old NT hash, so the hash alone proves the change. Pin the method because the hash cannot drive `kpasswd` or `ldap`.

=== "Set the new password by NT hash"

    Set the new password directly from a raw NT hash, proving the old password and needing no privilege:

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-hash <NTHASH>
    ```

    `--target-new-hash` pins `samr-des` on its own, so no `--method` is needed. The change bypasses the password policy, drops the account's Kerberos keys until its next cleartext change, and flags the password as expired.

=== "kpasswd"

    Change over the Kerberos change protocol (framed with version `0xFF80`):

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!' --method kpasswd
    ```

    `kpasswd` needs the cleartext old password to obtain the change ticket, so use `--target-old-password`, not `--target-old-hash`.

=== "LDAP over sealed 389"

    Change through the LDAP `unicodePwd` modify over a sealed connection on 389:

    ```
    passwolf change --target-domain corp.local --target-user jdoe --dc dc01.corp.local --target-old-password 'OldPass1!' --target-new-password 'NewPass1!' --method ldap
    ```

    The connection is signed and encrypted, so it does not require a certificate. Add `--ldaps` to ride TLS on 636 instead.

=== "Machine account over Netlogon"

    Rotate a machine account secret over the Netlogon secure channel:

    ```
    passwolf change --target-domain corp.local --target-user 'WS01$' --dc dc01.corp.local --account machine --target-old-password 'OldMachinePw' --target-new-password 'NewMachinePw' --netbios CORP
    ```

    `--account machine` routes the change to `NetrServerPasswordSet2` (opnum 30), falling back to the DES OWF change at opnum 6. Quote the account name because it ends in `$`.

## Exit status

`passwolf change` exits `0` on a successful change, `1` on a failed or unavailable method, and `2` on a usage error.

!!! warning "Credentials on the command line"
    Passwords and hashes passed as arguments can be visible to other local users through the process list. On a shared host, prefer a method that reads the secret from somewhere other than `argv`, or run from a host where the process table is not exposed.

## See also

- [Choosing a method](choosing-a-method.md) for change versus reset and which method to pick.
- [Change methods](../internals/change-methods.md) for the wire detail behind each method.
- [Output formats](output-formats.md) for `pretty`, `text`, and `json`.
- [Methods matrix](../methods.md) for the full method-by-method comparison.
