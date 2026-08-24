"""The ``dataweir`` command line."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import read_records, verify_chain
from .controls import CONTROLS, OWASP_ASI, control
from .policy import Policy, PolicyError, Severity
from .scan import run_scan
from .scan.findings import ScanReport

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STARTER_POLICY = """\
# dataweir policy — https://github.com/skv-se/dataweir
version: 1
name: starter

# Deny by default: an agent may do exactly what a grant allows, nothing more.
default: deny

# monitor -> record only (safe first install)
# warn    -> record and warn
# enforce -> block, and cap oversized reads
mode: monitor

audit:
  path: ./dataweir-audit.jsonl
  hash_chain: true
  redact_params: true

classification:
  sensitive_columns:
    - "*.ssn"
    - "*.password*"
    - "*.card_number"
  pii_columns:
    - "*.email"
    - "*.phone"
    - "*.address"

agents:
  - id: support-copilot
    description: Answers customer questions from ticket data.
    grants:
      - tables: [tickets]
        operations: [select]
        max_rows: 200
      - tables: [customers]
        operations: [select]
        columns: [customers.id, customers.name, customers.tier]
        deny_columns: [customers.ssn, customers.email]
        max_rows: 50
    budgets:
      rows_per_session: 2000
      rows_per_minute: 500
      sensitive_rows_per_session: 0
    anomaly:
      row_zscore: 4.0
      min_observations: 20
"""


def _short_time(ts: object) -> str:
    """`2026-08-23T21:56:55.327Z` -> `21:56:55`. The date is printed above the table."""
    text = str(ts)
    if len(text) >= 19 and text[10] == "T":
        return text[11:19]
    return text[:8]


def _load(policy_path: str) -> Policy:
    try:
        return Policy.load(policy_path)
    except PolicyError as err:
        err_console.print(f"[bold red]policy error:[/] {err}")
        raise SystemExit(2) from err


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="dataweir")
def main() -> None:
    """A data-layer guardrail and activity monitor for AI agents."""


# -- scan ----------------------------------------------------------------


@main.command()
@click.option(
    "--policy",
    "-p",
    "policy_path",
    default="dataweir.yaml",
    show_default=True,
    help="Policy file to red-team.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option("--output", "-o", type=click.Path(dir_okay=False), help="Write the report to a file.")
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default="high",
    show_default=True,
    help="Exit non-zero when a finding at or above this severity is present.",
)
@click.option("--static-only", is_flag=True, help="Skip the attack probes.")
@click.option("--probes-only", is_flag=True, help="Skip the policy-document checks.")
def scan(
    policy_path: str,
    output_format: str,
    output: str | None,
    fail_on: str,
    static_only: bool,
    probes_only: bool,
) -> None:
    """Red-team a policy: static weaknesses plus attack probes.

    Runs entirely offline — no database connection is opened — so it is safe in
    CI. Exits 1 when anything at or above --fail-on is found.
    """
    policy = _load(policy_path)
    report = run_scan(policy, static=not probes_only, probes=not static_only)

    if output_format == "json":
        payload = json.dumps(report.to_dict(), indent=2)
        if output:
            Path(output).write_text(payload + "\n", encoding="utf-8")
            console.print(f"wrote {output}")
        else:
            click.echo(payload)
    else:
        _print_report(report)
        if output:
            Path(output).write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
            console.print(f"\nJSON report written to {output}")

    raise SystemExit(report.exit_code(Severity(fail_on)))


def _print_report(report: ScanReport) -> None:
    console.print()
    console.print(
        f"[bold]dataweir scan[/] · policy [cyan]{report.policy_name}[/]"
        + (f" ([dim]{report.policy_path}[/])" if report.policy_path else "")
    )
    console.print(
        f"[dim]{report.checks_run} static checks · {report.probes_run} probes run, "
        f"{report.probes_passed} caught"
        + (f", {report.probes_skipped} skipped" if report.probes_skipped else "")
        + "[/]"
    )
    console.print()

    if not report.findings:
        console.print("[bold green]No findings.[/] This policy holds up against every probe.")
        return

    for finding in report.sorted_findings():
        badge = f"[{SEVERITY_STYLE[finding.severity]}] {finding.severity.value.upper()} [/]"
        owasp = ", ".join(finding.owasp)
        console.print(
            f"{badge} [bold]{finding.id}[/]  {finding.title}"
            + (f"  [dim]({owasp})[/]" if owasp else "")
        )
        if finding.subject:
            console.print(f"        [dim]subject:[/] {finding.subject}")
        console.print(f"        {finding.detail}", highlight=False)
        if finding.evidence:
            console.print(f"        [dim]tried:[/] [italic]{finding.evidence}[/]", highlight=False)
        console.print(f"        [green]fix:[/] {finding.remediation}", highlight=False)
        console.print()

    summary = " · ".join(
        f"[{SEVERITY_STYLE[Severity(name)]}]{count} {name}[/]"
        for name, count in report.counts.items()
        if count
    )
    console.print(f"[bold]{len(report.findings)} finding(s):[/] {summary}")


# -- policy --------------------------------------------------------------


@main.group()
def policy() -> None:
    """Create and check policy files."""


@policy.command("init")
@click.option(
    "--output",
    "-o",
    default="dataweir.yaml",
    show_default=True,
    type=click.Path(dir_okay=False),
)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def policy_init(output: str, force: bool) -> None:
    """Write a starter policy you can edit."""
    path = Path(output)
    if path.exists() and not force:
        err_console.print(f"[bold red]refusing to overwrite[/] {path} (use --force)")
        raise SystemExit(2)
    path.write_text(STARTER_POLICY, encoding="utf-8")
    console.print(f"[green]wrote[/] {path}")
    console.print(f"[dim]next:[/] dataweir scan --policy {path}")


@policy.command("validate")
@click.option("--policy", "-p", "policy_path", default="dataweir.yaml", show_default=True)
def policy_validate(policy_path: str) -> None:
    """Parse a policy and print what it grants."""
    loaded = _load(policy_path)
    console.print(
        f"[green]valid[/] · [bold]{loaded.name}[/] · default=[cyan]{loaded.default}[/] "
        f"· mode=[cyan]{loaded.mode.value}[/] · {len(loaded.agents)} agent(s)"
    )

    table = Table(header_style="bold")
    table.add_column("Agent")
    table.add_column("Tables")
    table.add_column("Operations")
    table.add_column("Max rows", justify="right")
    table.add_column("Session budget", justify="right")

    for agent in loaded.agents.values():
        if not agent.grants:
            table.add_row(agent.id, "[dim]— none —[/]", "—", "—", "—")
            continue
        for index, grant in enumerate(agent.grants):
            budget = agent.budgets.rows_per_session
            table.add_row(
                agent.id if index == 0 else "",
                ", ".join(grant.tables),
                ", ".join(sorted(op.value for op in grant.operations)),
                str(grant.max_rows) if grant.max_rows is not None else "[red]none[/]",
                (str(budget) if budget is not None else "[dim]none[/]") if index == 0 else "",
            )

    console.print(table)


# -- audit ---------------------------------------------------------------


@main.group()
def audit() -> None:
    """Inspect the audit log."""


@audit.command("verify")
@click.argument("path", default="dataweir-audit.jsonl")
def audit_verify(path: str) -> None:
    """Recompute the hash chain and report any tampering."""
    if not Path(path).exists():
        err_console.print(f"[bold red]no such audit file:[/] {path}")
        raise SystemExit(2)
    report = verify_chain(path)
    if report.ok:
        console.print(f"[bold green]OK[/] · {report}")
        raise SystemExit(0)
    console.print(f"[bold red]TAMPERED[/] · {report}")
    raise SystemExit(1)


@audit.command("tail")
@click.argument("path", default="dataweir-audit.jsonl")
@click.option("-n", "count", default=20, show_default=True, help="Records to show.")
@click.option("--agent", help="Only this agent.")
@click.option("--code", help="Only records containing this control code.")
@click.option("--blocked", is_flag=True, help="Only blocked or observed-block decisions.")
@click.option(
    "--event",
    type=click.Choice(["decision", "result", "all"]),
    default="all",
    show_default=True,
    help="`decision` is the pre-execution verdict; `result` carries the row count.",
)
def audit_tail(
    path: str, count: int, agent: str | None, code: str | None, blocked: bool, event: str
) -> None:
    """Show the most recent decisions."""
    if not Path(path).exists():
        err_console.print(f"[bold red]no such audit file:[/] {path}")
        raise SystemExit(2)

    records = []
    for record in read_records(path):
        if event != "all" and record.get("event") != event:
            continue
        if agent and record.get("agent_id") != agent:
            continue
        codes = [f.get("code") for f in record.get("findings", [])]
        if code and code.upper() not in codes:
            continue
        if blocked and record.get("action") not in ("blocked", "observed"):
            continue
        records.append(record)

    shown = records[-count:]

    # Six columns of full timestamps do not fit an 80-column terminal, and the
    # SQL is the part worth reading. The date goes in the header instead.
    dates = sorted({str(record.get("ts", ""))[:10] for record in shown if record.get("ts")})
    if dates:
        span = dates[0] if len(dates) == 1 else f"{dates[0]} to {dates[-1]}"
        console.print(f"[dim]{span} · times are UTC[/]")

    table = Table(header_style="bold", expand=True)
    table.add_column("Time", width=8, no_wrap=True)
    table.add_column("Agent", width=14, overflow="ellipsis", no_wrap=True)
    table.add_column("Action", width=9, no_wrap=True)
    table.add_column("Rows", justify="right", width=5)
    table.add_column("Codes", width=13, overflow="fold")
    table.add_column("SQL", ratio=1, overflow="ellipsis", no_wrap=True)

    for record in shown:
        action = str(record.get("action", ""))
        style = {
            "blocked": "bold red",
            "observed": "yellow",
            "warned": "yellow",
            "rewritten": "cyan",
        }.get(action, "green")
        rows = record.get("rows_returned")
        table.add_row(
            _short_time(record.get("ts", "")),
            str(record.get("agent_id", "")),
            f"[{style}]{action}[/]",
            "—" if rows is None else str(rows),
            " ".join(f.get("code", "") for f in record.get("findings", [])) or "—",
            str(record.get("sql", "")).replace("\n", " "),
        )

    console.print(table)
    console.print(f"[dim]{len(records)} matching record(s); showing last {len(shown)}[/]")


@audit.command("summary")
@click.argument("path", default="dataweir-audit.jsonl")
def audit_summary(path: str) -> None:
    """Aggregate an audit log: who did what, and what fired."""
    if not Path(path).exists():
        err_console.print(f"[bold red]no such audit file:[/] {path}")
        raise SystemExit(2)

    agents: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    rows_by_agent: Counter[str] = Counter()
    total = 0

    for record in read_records(path):
        total += 1
        agent_id = str(record.get("agent_id", "?"))
        agents[agent_id] += 1
        actions[str(record.get("action", "?"))] += 1
        for finding in record.get("findings", []):
            codes[str(finding.get("code"))] += 1
        rows = record.get("rows_returned")
        if isinstance(rows, int):
            rows_by_agent[agent_id] += rows

    console.print(f"\n[bold]{total}[/] record(s) in [dim]{path}[/]\n")

    agent_table = Table(title="By agent", header_style="bold", title_justify="left")
    agent_table.add_column("Agent")
    agent_table.add_column("Decisions", justify="right")
    agent_table.add_column("Rows drawn", justify="right")
    for agent_id, decisions in agents.most_common():
        agent_table.add_row(agent_id, str(decisions), str(rows_by_agent[agent_id]))
    console.print(agent_table)

    action_table = Table(title="By action", header_style="bold", title_justify="left")
    action_table.add_column("Action")
    action_table.add_column("Count", justify="right")
    for action, occurrences in actions.most_common():
        action_table.add_row(action, str(occurrences))
    console.print(action_table)

    if codes:
        code_table = Table(title="Controls fired", header_style="bold", title_justify="left")
        code_table.add_column("Code")
        code_table.add_column("Control")
        code_table.add_column("Count", justify="right")
        for code_id, occurrences in codes.most_common():
            try:
                title = control(code_id).title
            except KeyError:
                title = "—"
            code_table.add_row(code_id, title, str(occurrences))
        console.print(code_table)


# -- reference -----------------------------------------------------------


@main.command("controls")
@click.argument("code", required=False)
def controls_command(code: str | None) -> None:
    """List the control catalog, or explain one control."""
    if code:
        try:
            item = control(code.upper())
        except KeyError:
            err_console.print(f"[bold red]unknown control:[/] {code}")
            raise SystemExit(2) from None
        console.print(f"\n[bold]{item.code}[/] · {item.title}")
        console.print(f"severity : [{SEVERITY_STYLE[item.severity]}]{item.severity.value}[/]")
        console.print(
            "owasp    : " + ", ".join(f"{c} {OWASP_ASI.get(c, '')}".strip() for c in item.owasp)
        )
        console.print(f"fix      : {item.remediation}\n")
        return

    table = Table(header_style="bold", expand=True)
    table.add_column("Code", width=8)
    table.add_column("Control", width=38)
    table.add_column("Severity", width=10)
    table.add_column("OWASP Agentic Top 10", ratio=1)
    for item in CONTROLS.values():
        table.add_row(
            item.code,
            item.title,
            f"[{SEVERITY_STYLE[item.severity]}]{item.severity.value}[/]",
            ", ".join(f"{c} {OWASP_ASI.get(c, '')}".strip() for c in item.owasp),
        )
    console.print(table)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
