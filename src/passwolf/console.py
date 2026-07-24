# SPDX-License-Identifier: Apache-2.0
"""Result rendering in text, JSON, and rich-pretty forms.

A single :class:`Outcome` record captures what happened so the three formatters stay consistent. rich
is imported lazily inside the pretty formatter so the common text and JSON paths have no rich import
cost, matching the sibling tools.
"""

from __future__ import annotations

import io
import json
import math
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import nterror
from .model import OutputFormat

if TYPE_CHECKING:
    from rich.console import Console

    from .policymodel import GptTmplPolicy, PasswordPolicy, PolicyReadResult, PsoPolicy, UserPolicyView


@dataclass
class Outcome:
    """The result of one change or reset attempt, formatter-agnostic."""

    operation: str
    method: str
    target: str
    dc: str
    status: int
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Whether the operation returned STATUS_SUCCESS."""
        return nterror.is_success(self.status)

    @property
    def status_name(self) -> str:
        """The symbolic NTSTATUS name of the result."""
        return nterror.name(self.status)


def _format_text(outcome: Outcome) -> str:
    """Render a single, greppable status line plus any extra key/value detail."""
    verb = "ok" if outcome.success else "FAIL"
    head = f"[{verb}] {outcome.operation} {outcome.target} via {outcome.method} on {outcome.dc}: {nterror.describe(outcome.status)}"
    lines = [head]
    lines.extend(f"      {key}: {value}" for key, value in outcome.extra.items())
    return "\n".join(lines)


def _format_json(outcome: Outcome) -> str:
    """Render the outcome as a single JSON object."""
    payload = {
        "operation": outcome.operation,
        "method": outcome.method,
        "target": outcome.target,
        "dc": outcome.dc,
        "success": outcome.success,
        "status": f"0x{outcome.status & 0xFFFFFFFF:08X}",
        "status_name": outcome.status_name,
        "detail": nterror.describe(outcome.status),
        "extra": outcome.extra,
    }
    return json.dumps(payload, indent=2)


def _format_pretty(outcome: Outcome) -> str:
    """Render a rich panel; rich is imported only here."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(justify="right", style="bold")
    table.add_column()
    table.add_row("operation", outcome.operation)
    table.add_row("target", outcome.target)
    table.add_row("dc", outcome.dc)
    table.add_row("method", outcome.method)
    table.add_row("status", nterror.describe(outcome.status))
    for key, value in outcome.extra.items():
        table.add_row(key, value)

    style = "green" if outcome.success else "red"
    title = "success" if outcome.success else "failed"
    # Record into a throwaway buffer so .print() does not also write to stdout (the caller prints the export).
    buffer = Console(record=True, width=100, file=io.StringIO())
    buffer.print(Panel(table, title=title, border_style=style))
    # Keep the success/failure colors on a terminal, but emit a plain panel when piped to a file or log.
    return buffer.export_text(styles=sys.stdout.isatty()).rstrip("\n")


_FORMATTERS = {
    OutputFormat.TEXT: _format_text,
    OutputFormat.JSON: _format_json,
    OutputFormat.PRETTY: _format_pretty,
}


def render(outcome: Outcome, fmt: OutputFormat) -> str:
    """Render an outcome in the requested output format."""
    return _FORMATTERS[fmt](outcome)


# --- Password-policy read rendering ---
def _num(value: float) -> str:
    """Render a numeric policy value, collapsing the never sentinel and dropping trailing zeros."""
    if math.isinf(value):
        return "never"
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def _flag(value: bool | None) -> str:
    """Render a tri-state boolean policy field (enabled / disabled / unknown)."""
    if value is None:
        return "unknown"
    return "enabled" if value else "disabled"


class _Rows:
    """A small typed accumulator of present fields, exposing both a display and a JSON view.

    Each ``add_*`` method takes a stable JSON key, a human display label, and one optional value, appending
    a row only when the value is set. The display view (:attr:`display`) renders the official Microsoft
    label with the unit folded into the value (for example ``"42 days"``); the JSON view (:attr:`json`)
    keeps the stable snake_case key and a unitless value, so machine consumers are not handed display text.
    """

    def __init__(self) -> None:
        # Each row is (json_key, display_label, rendered_value, unit-or-None).
        self._rows: list[tuple[str, str, str, str | None]] = []

    def add_text(self, key: str, label: str, value: str | None) -> None:
        """Append a string field when present."""
        if value is not None:
            self._rows.append((key, label, value, None))

    def add_int(self, key: str, label: str, value: int | None) -> None:
        """Append an integer (count) field when present; counts carry no unit."""
        if value is not None:
            self._rows.append((key, label, str(value), None))

    def add_num(self, key: str, label: str, value: float | None, unit: str | None = None) -> None:
        """Append a numeric (age/window) field when present, collapsing the never sentinel.

        The unit is folded into the display value but kept off the never sentinel and out of the JSON view.
        """
        if value is not None:
            self._rows.append((key, label, _num(value), unit))

    def add_flag(self, key: str, label: str, value: bool | None) -> None:
        """Append a tri-state boolean field when present."""
        if value is not None:
            self._rows.append((key, label, _flag(value), None))

    def add_yes_no(self, key: str, label: str, value: bool | None) -> None:
        """Append a yes/no field when present."""
        if value is not None:
            self._rows.append((key, label, "yes" if value else "no", None))

    def __len__(self) -> int:
        """Return the number of present fields (used to pick the most complete record per scope)."""
        return len(self._rows)

    @property
    def display(self) -> list[tuple[str, str]]:
        """The (label, value) pairs for text and pretty output, with units folded into the value."""
        return [(label, f"{value} {unit}" if unit and value != "never" else value) for _key, label, value, unit in self._rows]

    @property
    def json(self) -> dict[str, str]:
        """The stable {json_key: value} mapping for JSON output, with no units or display labels."""
        return {key: value for key, _label, value, _unit in self._rows}


# The official Group Policy setting names Microsoft uses in secpol.msc and the Microsoft Learn password and
# account-lockout policy documentation. Each field below pairs one of these with the protocol field it was
# read from (a [MS-SAMR] struct field, an [MS-ADTS] msDS- attribute, or a SYSVOL GptTmpl.inf key), so the
# label is both admin-recognizable and traceable to the wire.
_GPO_NAME = {
    "min_length": "Minimum password length",
    "history": "Enforce password history",
    "max_age": "Maximum password age",
    "min_age": "Minimum password age",
    "complexity": "Password must meet complexity requirements",
    "reversible": "Store passwords using reversible encryption",
    "lockout_threshold": "Account lockout threshold",
    "lockout_duration": "Account lockout duration",
    "lockout_reset": "Reset account lockout counter after",
}


def _label(key: str, spec_field: str | None = None) -> str:
    """Compose an official Group Policy label, with the source protocol field appended in parentheses."""
    name = _GPO_NAME[key]
    return f"{name} ({spec_field})" if spec_field else name


def _policy_rows(policy: PasswordPolicy) -> _Rows:
    """Reduce a PasswordPolicy to its present fields, labelled with the SAMR struct field names it carries."""
    rows = _Rows()
    rows.add_int("minimum_password_length", _label("min_length", "MinPasswordLength"), policy.min_password_length)
    rows.add_int("enforce_password_history", _label("history", "PasswordHistoryLength"), policy.password_history_length)
    rows.add_num("maximum_password_age", _label("max_age", "MaxPasswordAge"), policy.max_password_age_days, "days")
    rows.add_num("minimum_password_age", _label("min_age", "MinPasswordAge"), policy.min_password_age_days, "days")
    rows.add_flag("password_complexity", _label("complexity"), policy.complexity_enabled)
    rows.add_flag("reversible_encryption", _label("reversible"), policy.reversible_encryption)
    if policy.password_properties_raw is not None:
        rows.add_text("password_properties", "Password properties (PasswordProperties)", f"0x{policy.password_properties_raw:08X} {' '.join(policy.property_flags) or '(none)'}")
    rows.add_int("account_lockout_threshold", _label("lockout_threshold", "LockoutThreshold"), policy.lockout_threshold)
    rows.add_num("account_lockout_duration", _label("lockout_duration", "LockoutDuration"), policy.lockout_duration_minutes, "min")
    rows.add_num("reset_account_lockout_counter_after", _label("lockout_reset", "LockoutObservationWindow"), policy.lockout_observation_window_minutes, "min")
    rows.add_num("force_logoff", "Force logoff (ForceLogoff)", policy.force_logoff_seconds, "sec")
    return rows


def _pso_rows(pso: PsoPolicy) -> _Rows:
    """Reduce a PsoPolicy to its present fields, labelled with the msDS- attribute names it was read from."""
    rows = _Rows()
    if pso.read_status != "ok":
        rows.add_text("read", "Read", "denied (values hidden by the container ACL)")
        return rows
    rows.add_int("precedence", "Precedence (msDS-PasswordSettingsPrecedence)", pso.precedence)
    rows.add_int("minimum_password_length", _label("min_length", "msDS-MinimumPasswordLength"), pso.min_password_length)
    rows.add_int("enforce_password_history", _label("history", "msDS-PasswordHistoryLength"), pso.password_history_length)
    rows.add_num("maximum_password_age", _label("max_age", "msDS-MaximumPasswordAge"), pso.max_password_age_days, "days")
    rows.add_num("minimum_password_age", _label("min_age", "msDS-MinimumPasswordAge"), pso.min_password_age_days, "days")
    rows.add_flag("password_must_meet_complexity_requirements", _label("complexity", "msDS-PasswordComplexityEnabled"), pso.complexity_enabled)
    rows.add_flag("store_passwords_using_reversible_encryption", _label("reversible", "msDS-PasswordReversibleEncryptionEnabled"), pso.reversible_encryption)
    rows.add_int("account_lockout_threshold", _label("lockout_threshold", "msDS-LockoutThreshold"), pso.lockout_threshold)
    rows.add_num("account_lockout_duration", _label("lockout_duration", "msDS-LockoutDuration"), pso.lockout_duration_minutes, "min")
    rows.add_num("reset_account_lockout_counter_after", _label("lockout_reset", "msDS-LockoutObservationWindow"), pso.lockout_observation_window_minutes, "min")
    rows.add_text("applies_to", "Applies to (msDS-PSOAppliesTo)", ", ".join(pso.applies_to) if pso.applies_to else None)
    return rows


def _gpo_rows(gpo: GptTmplPolicy) -> _Rows:
    """Reduce a GptTmplPolicy to its present fields, labelled with the GptTmpl.inf [System Access] keys."""
    rows = _Rows()
    rows.add_int("minimum_password_length", _label("min_length", "MinimumPasswordLength"), gpo.min_password_length)
    rows.add_int("enforce_password_history", _label("history", "PasswordHistorySize"), gpo.password_history_size)
    rows.add_num("maximum_password_age", _label("max_age", "MaximumPasswordAge"), gpo.max_password_age_days, "days")
    rows.add_num("minimum_password_age", _label("min_age", "MinimumPasswordAge"), gpo.min_password_age_days, "days")
    rows.add_flag("password_must_meet_complexity_requirements", _label("complexity", "PasswordComplexity"), gpo.complexity_enabled)
    rows.add_flag("store_passwords_using_reversible_encryption", _label("reversible", "ClearTextPassword"), gpo.reversible_encryption)
    rows.add_int("account_lockout_threshold", _label("lockout_threshold", "LockoutBadCount"), gpo.lockout_threshold)
    rows.add_num("account_lockout_duration", _label("lockout_duration", "LockoutDuration"), gpo.lockout_duration_minutes, "min")
    rows.add_num("reset_account_lockout_counter_after", _label("lockout_reset", "ResetLockoutCount"), gpo.reset_lockout_minutes, "min")
    return rows


def _user_rows(view: UserPolicyView) -> _Rows:
    """Reduce a UserPolicyView to its present fields (the assembled policies render separately)."""
    rows = _Rows()
    rows.add_text("principal", "Principal", view.principal)
    rows.add_text("resultant_pso", "Resultant PSO (msDS-ResultantPSO)", view.resultant_pso or "(default domain policy)")
    rows.add_int("effective_minimum_password_length", "Effective minimum password length (op44)", view.op44_min_length)
    rows.add_flag("effective_password_complexity", "Effective password complexity (op44)", view.op44_complexity)
    rows.add_yes_no("locked_out", "Locked out (UF_LOCKOUT)", view.is_locked_out)
    rows.add_yes_no("password_expired", "Password expired (UF_PASSWORD_EXPIRED)", view.password_expired)
    rows.add_int("bad_password_count", "Bad password count (badPwdCount)", view.bad_password_count)
    return rows


# The scope each method speaks to, so the comparison table labels every row even when the method was
# denied (and so produced no record to read a scope from). "domain" is the domain-wide default policy,
# "PSO" a per-user fine-grained effective policy, and "account" the live per-user account state.
_METHOD_SCOPE = {
    "samr-query": "domain",
    "samr-getdompwinfo": "domain",
    "samr-getusrpwinfo": "PSO",
    "samr-diag": "PSO",
    "kpasswd": "PSO",
    "ldap-domain-head": "domain",
    "ldap-pso": "PSO",
    "ldap-resultant": "PSO",
    "ldap-uac": "account",
    "sysvol": "domain",
}

# Every policy field gets a comparison column, so the grid is a complete cross-method view. Headers carry
# their unit where the bare number would be ambiguous: (d) days, (m) minutes, (s) seconds. The three
# lockout fields are named apart (threshold / duration / reset) so no header is ambiguous.
_COMPARISON_HEADER = (
    "method",
    "scope",
    "status",
    "min len",
    "history",
    "max age (d)",
    "min age (d)",
    "complexity",
    "reversible",
    "lockout thr",
    "lockout dur (m)",
    "lockout reset (m)",
    "force logoff (s)",
)


def _comparison_rows(result: PolicyReadResult) -> list[tuple[str, ...]]:
    """Build one comparison row per method: its scope, verdict, and every policy field side by side.

    The point of running every method is to see where they agree and disagree (a PSO makes the per-user
    oracles report a different minimum than the domain reads), so each method is matched to the record it
    produced and all of its fields are laid out in one aligned table; a method that did not fill a field
    shows ``-`` there. The scope column says whether the row is the domain default or a PSO (fine-grained)
    effective policy; it falls back to the static map when the method was denied and left no record.
    """
    records = list(result.policies)

    rows: list[tuple[str, ...]] = []
    for method_id, status in result.reachability.items():
        r = next((rec for rec in records if rec.source.startswith(method_id)), None)
        scope = r.scope if r is not None else _METHOD_SCOPE.get(method_id, "-")
        rows.append(
            (
                method_id,
                scope,
                status.split(":", 1)[0],  # the short verdict; full detail stays in the reachability section
                "-" if r is None or r.min_password_length is None else str(r.min_password_length),
                "-" if r is None or r.password_history_length is None else str(r.password_history_length),
                "-" if r is None or r.max_password_age_days is None else _num(r.max_password_age_days),
                "-" if r is None or r.min_password_age_days is None else _num(r.min_password_age_days),
                "-" if r is None or r.complexity_enabled is None else _flag(r.complexity_enabled),
                "-" if r is None or r.reversible_encryption is None else _flag(r.reversible_encryption),
                "-" if r is None or r.lockout_threshold is None else str(r.lockout_threshold),
                "-" if r is None or r.lockout_duration_minutes is None else _num(r.lockout_duration_minutes),
                "-" if r is None or r.lockout_observation_window_minutes is None else _num(r.lockout_observation_window_minutes),
                "-" if r is None or r.force_logoff_seconds is None else _num(r.force_logoff_seconds),
            ),
        )
    return rows


def _aligned_table(header: tuple[str, ...], rows: list[tuple[str, ...]], indent: str) -> list[str]:
    """Format a header and rows into left-aligned, padded columns (the text/greppable table form)."""
    widths = [max(len(row[i]) for row in (header, *rows)) for i in range(len(header))]

    def fmt(row: tuple[str, ...]) -> str:
        return indent + "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip()

    return [fmt(header), fmt(tuple("-" * width for width in widths)), *(fmt(row) for row in rows)]


def _policy_text(result: PolicyReadResult) -> str:
    """Render the policy read as greppable indented sections, grouped by scope (domain vs PSO)."""
    lines = [f"password policy for {result.target} on {result.dc}"]
    comparison = _comparison_rows(result)
    if comparison:
        lines.append("  [methods]")
        lines.extend(_aligned_table(_COMPARISON_HEADER, comparison, "      "))
    # Split the policy records into the domain default and the per-user PSO-effective reads so the two are
    # never confused; each source keeps its own sub-block under the scope header.
    domain_policies = [p for p in result.policies if p.scope == "domain"]
    pso_policies = [p for p in result.policies if p.scope != "domain"]
    if domain_policies:
        lines.append("  [domain password policy]")
        for policy in domain_policies:
            lines.append(f"    {policy.source}")
            lines.extend(f"      {label}: {value}" for label, value in _policy_rows(policy).display)
    if pso_policies:
        lines.append("  [PSO (fine-grained) effective policy]")
        for policy in pso_policies:
            lines.append(f"    {policy.source}")
            lines.extend(f"      {label}: {value}" for label, value in _policy_rows(policy).display)
    for pso in result.psos:
        lines.append(f"  [PSO object: {pso.name}]")
        lines.extend(f"      {label}: {value}" for label, value in _pso_rows(pso).display)
    for gpo in result.gpo_policies:
        lines.append(f"  [domain configured intent: GPO {gpo.gpo_name} {gpo.gpo_guid}]")
        lines.extend(f"      {label}: {value}" for label, value in _gpo_rows(gpo).display)
    if result.user_view is not None:
        lines.append("  [target user]")
        lines.extend(f"      {label}: {value}" for label, value in _user_rows(result.user_view).display)
        if result.user_view.effective_pso is not None:
            lines.append("  [winning PSO]")
            lines.extend(f"      {label}: {value}" for label, value in _pso_rows(result.user_view.effective_pso).display)
    lines.append("  [reachability]")
    lines.extend(f"      {method}: {status}" for method, status in result.reachability.items())
    return "\n".join(lines)


def _policy_json(result: PolicyReadResult) -> str:
    """Render the policy read as one JSON object with stable snake_case keys and normalized values.

    The JSON view keeps machine-friendly keys (no official display labels, no units) so consumers can index
    fields directly; the human-facing labels live only in the text and pretty formats.
    """
    payload: dict[str, object] = {
        "target": result.target,
        "dc": result.dc,
        "policies": [{"source": p.source, "scope": p.scope, **_policy_rows(p).json} for p in result.policies],
        "psos": [{"name": p.name, "read_status": p.read_status, **_pso_rows(p).json} for p in result.psos],
        "gpo_policies": [{"gpo": g.gpo_name, "guid": g.gpo_guid, **_gpo_rows(g).json} for g in result.gpo_policies],
        "reachability": result.reachability,
    }
    if result.user_view is not None:
        view = result.user_view
        payload["user_view"] = {
            **_user_rows(view).json,
            "effective_pso": _pso_rows(view.effective_pso).json if view.effective_pso is not None else None,
        }
    return json.dumps(payload, indent=2)


# Color per reachability verdict, used to tint the status cells in the pretty dashboard.
_STATUS_COLOR = {"ok": "green", "denied": "red", "unavailable": "red", "failed": "red", "skipped": "yellow"}
# Color per scope, so domain-default and PSO (fine-grained) rows are distinguishable at a glance.
_SCOPE_COLOR = {"domain": "blue", "PSO": "magenta", "account": "yellow"}


def _emit_methods(buffer: Console, result: PolicyReadResult) -> None:
    """Print the boxed method-comparison table with colored scope and verdict (the dashboard centerpiece)."""
    from rich import box
    from rich.table import Table
    from rich.text import Text

    rows = _comparison_rows(result)
    if not rows:
        return
    table = Table(title="methods", box=box.ROUNDED, title_style="bold", title_justify="left", header_style="bold cyan")
    for column in _COMPARISON_HEADER:
        table.add_column(column)
    for row in rows:
        # row is (method, scope, status, *values); tint the scope and status cells, leave the rest plain.
        scope_cell = Text(row[1], style=_SCOPE_COLOR.get(row[1], "white"))
        status_cell = Text(row[2], style=_STATUS_COLOR.get(row[2], "white"))
        table.add_row(row[0], scope_cell, status_cell, *row[3:])
    buffer.print(table)


def _emit_kv(buffer: Console, title: str, rows: list[tuple[str, str]]) -> None:
    """Print one boxed key/value detail table, skipping it when there is nothing to show."""
    from rich import box
    from rich.table import Table

    if not rows:
        return
    table = Table(title=title, box=box.SIMPLE, show_header=False, title_style="bold", title_justify="left", pad_edge=False)
    table.add_column(justify="right", style="bold cyan")
    table.add_column()
    for label, value in rows:
        table.add_row(label, value)
    buffer.print(table)


def _richest_scope(result: PolicyReadResult, scope: str) -> PasswordPolicy | None:
    """Pick the most complete record of one scope so a single detail table covers the full policy.

    Several methods report the same scope at different completeness (op44 carries only length and
    complexity, the oracle the full block), so the winner is whichever record filled the most fields.
    """
    candidates = [p for p in result.policies if p.scope == scope]
    return max(candidates, key=lambda p: len(_policy_rows(p))) if candidates else None


def _emit_detail(buffer: Console, result: PolicyReadResult) -> None:
    """Print the boxed detail tables, kept compact: one box for the domain default, one for the PSO-effective."""
    domain = _richest_scope(result, "domain")
    if domain is not None:
        _emit_kv(buffer, "domain password policy", _policy_rows(domain).display)
    effective = _richest_scope(result, "PSO")
    if effective is not None:
        _emit_kv(buffer, "PSO (fine-grained) effective policy", _policy_rows(effective).display)
    view = result.user_view
    if view is not None:
        _emit_kv(buffer, f"target user: {view.principal}", _user_rows(view).display)
        if view.effective_pso is not None:
            _emit_kv(buffer, "winning PSO", _pso_rows(view.effective_pso).display)
    for pso in result.psos:
        _emit_kv(buffer, f"PSO object: {pso.name}", _pso_rows(pso).display)
    for gpo in result.gpo_policies:
        # The GUID is too wide for a box title (it would wrap), so it rides in a row; the title keeps a
        # friendly display name only when the GPO actually has one distinct from its GUID.
        title = f"GPO {gpo.gpo_name}" if gpo.gpo_name != gpo.gpo_guid else "GPO (configured intent)"
        _emit_kv(buffer, title, [("GUID", gpo.gpo_guid), *_gpo_rows(gpo).display])


def _emit_issues(buffer: Console, result: PolicyReadResult) -> None:
    """Print the boxed table of methods that were not reached, with their full reason."""
    from rich import box
    from rich.table import Table
    from rich.text import Text

    not_reached = {method: status for method, status in result.reachability.items() if status != "ok"}
    if not not_reached:
        return
    table = Table(title="not reached", box=box.ROUNDED, title_style="bold", title_justify="left", header_style="bold")
    table.add_column("method")
    table.add_column("reason")
    for method, status in not_reached.items():
        table.add_row(method, Text(status, style=_STATUS_COLOR.get(status.split(":", 1)[0], "white")))
    buffer.print(table)


def _policy_pretty(result: PolicyReadResult) -> str:
    """Render the policy read as a compact boxed dashboard; rich is imported only here."""
    from rich import box
    from rich.console import Console
    from rich.panel import Panel

    # Record into a throwaway buffer so .print() does not also write to stdout (the caller prints the export).
    # The width fits the full methods table (method + scope + status + every policy field) without truncation;
    # the detail boxes size to their own content, so the extra width is only spent where the grid needs it.
    buffer = Console(record=True, width=200, file=io.StringIO())
    buffer.print(Panel(f"[bold]{result.target}[/bold] on [bold]{result.dc}[/bold]", title="password policy", title_align="left", border_style="cyan", box=box.ROUNDED, expand=False))
    _emit_methods(buffer, result)
    _emit_detail(buffer, result)
    _emit_issues(buffer, result)
    # Keep the verdict colors when writing to a terminal, but emit plain boxes when piped to a file or log.
    return buffer.export_text(styles=sys.stdout.isatty()).rstrip("\n")


_POLICY_FORMATTERS = {
    OutputFormat.TEXT: _policy_text,
    OutputFormat.JSON: _policy_json,
    OutputFormat.PRETTY: _policy_pretty,
}


def render_policy(result: PolicyReadResult, fmt: OutputFormat) -> str:
    """Render a password-policy read in the requested output format."""
    return _POLICY_FORMATTERS[fmt](result)
