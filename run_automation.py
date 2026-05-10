"""
CLI runner for the GRC Control Automation engine.
Generates data, runs all detection rules, prints a rich summary to the terminal,
and optionally saves evidence packages and HTML reports.

Usage:
  python run_automation.py                    # run engine, print report
  python run_automation.py --save-evidence    # also save evidence package
  python run_automation.py --save-report      # also save HTML report
  python run_automation.py --all              # save everything
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows so Rich box-drawing characters render correctly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── Path setup ───────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from src.control_engine import compute_summary, run_all_rules
from src.data_generator import generate_all
from src.evidence_generator import generate_evidence_package
from src.report_builder import build_html_report
from src.risk_scorer import BAND_COLORS, BAND_ORDER

console = Console(highlight=False)

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


def banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]GRC Control Automation Platform[/bold white]\n"
        "[dim]DataStream Technologies · Privileged Access Review[/dim]\n"
        "[dim]SOC 2 Type II · PCI DSS v4.0 · ISO 27001:2022[/dim]",
        border_style="blue",
        padding=(1, 4),
    ))
    console.print()


def print_summary(summary: dict):
    console.print(Rule("[bold blue]Executive Summary[/bold blue]"))
    console.print()

    cards = []
    def _card(label: str, value: str, color: str = "blue") -> Panel:
        return Panel(
            f"[bold {color}]{value}[/bold {color}]\n[dim]{label}[/dim]",
            border_style=color, padding=(0, 2),
        )

    crit = summary.get("critical_findings", 0)
    high = summary.get("high_findings", 0)
    med  = summary.get("medium_findings", 0)
    low  = summary.get("low_findings", 0)

    cards.append(_card("Critical Findings", str(crit), "red" if crit > 0 else "green"))
    cards.append(_card("High Findings",     str(high), "yellow" if high > 0 else "green"))
    cards.append(_card("Medium Findings",   str(med),  "yellow"))
    cards.append(_card("Low Findings",      str(low),  "green"))
    cards.append(_card("Avg Risk Score",    str(summary.get("avg_risk_score", 0)), "blue"))
    cards.append(_card("Compliance Rate",   f"{summary.get('compliance_rate', 0)}%", "cyan"))

    console.print(Columns(cards, equal=True, expand=True))
    console.print()

    stats = Table(show_header=False, box=None, padding=(0, 2))
    stats.add_column(style="dim")
    stats.add_column(style="bold")
    stats.add_row("Active Employees",       str(summary.get("active_employees", 0)))
    stats.add_row("Access Records Reviewed", str(summary.get("total_access_records", 0)))
    stats.add_row("Affected Employees",     str(summary.get("affected_employees", 0)))
    stats.add_row("Affected Systems",       str(summary.get("affected_systems", 0)))
    stats.add_row("Total Findings",         str(summary.get("total_findings", 0)))
    console.print(stats)
    console.print()


def print_findings_table(findings):
    console.print(Rule("[bold blue]Top Findings by Risk Score[/bold blue]"))
    console.print()

    table = Table(
        show_header=True, header_style="bold blue",
        box=box.ROUNDED, border_style="dim",
        row_styles=["", "dim"],
    )
    table.add_column("Finding ID",  style="dim cyan",  no_wrap=True)
    table.add_column("Severity",    no_wrap=True)
    table.add_column("Risk",        justify="right", no_wrap=True)
    table.add_column("Type",        max_width=22)
    table.add_column("Employee",    max_width=24)
    table.add_column("Department",  max_width=16)
    table.add_column("System",      max_width=26)
    table.add_column("SLA",         no_wrap=True, max_width=20)

    for _, row in findings.head(30).iterrows():
        sev_style = SEVERITY_STYLE.get(row["severity"], "white")
        risk_style = "bold red" if row["risk_score"] >= 70 else ("yellow" if row["risk_score"] >= 40 else "green")
        table.add_row(
            row["finding_id"],
            Text(row["severity"], style=sev_style),
            Text(f"{row['risk_score']:.0f}", style=risk_style),
            row["finding_type"].replace("_", " ").title(),
            row["employee_name"],
            row["department"],
            row["system_name"],
            row["sla_deadline"][:16],
        )

    console.print(table)
    console.print()


def print_breakdown(summary: dict):
    console.print(Rule("[bold blue]Breakdown[/bold blue]"))
    console.print()

    left = Table("Finding Type", "Count", box=box.SIMPLE_HEAD, border_style="dim")
    for ft, cnt in summary.get("by_type", {}).items():
        left.add_row(ft.replace("_", " ").title(), str(cnt))

    right = Table("Department", "Count", box=box.SIMPLE_HEAD, border_style="dim")
    for dept, cnt in list(summary.get("by_department", {}).items())[:8]:
        right.add_row(dept, str(cnt))

    console.print(Columns([left, right], equal=True, expand=True))
    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="GRC Control Automation CLI — Privileged Access Review",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--save-evidence", action="store_true", help="Save evidence package to outputs/evidence/")
    parser.add_argument("--save-report",   action="store_true", help="Save HTML executive report to outputs/reports/")
    parser.add_argument("--all",           action="store_true", help="Enable --save-evidence and --save-report")
    parser.add_argument("--seed",          type=int, default=42, help="Random seed for reproducible data (default: 42)")
    args = parser.parse_args()

    if args.all:
        args.save_evidence = True
        args.save_report = True

    banner()

    # Generate data
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as prog:
        t1 = prog.add_task("Generating synthetic employee & access data…", total=None)
        start = time.time()
        datasets = generate_all(seed=args.seed)
        employees = datasets["employees"]
        access = datasets["access_rights"]
        prog.update(t1, description=f"Data generated in {time.time()-start:.2f}s")

        t2 = prog.add_task("Running detection rules…", total=None)
        findings = run_all_rules(employees, access)
        summary = compute_summary(findings, employees, access)
        prog.update(t2, description=f"Rules complete — {len(findings)} findings")

    console.print(f"[green][OK][/green] Data generation complete ({len(employees)} employees, {len(access)} access records)")
    console.print(f"[green][OK][/green] Detection engine complete — [bold]{len(findings)} findings[/bold] across {summary.get('affected_systems', 0)} systems")
    console.print()

    if findings.empty:
        console.print("[bold green]🎉 No findings — all controls passing![/bold green]")
        return

    print_summary(summary)
    print_findings_table(findings)
    print_breakdown(summary)

    if args.save_evidence:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as prog:
            prog.add_task("Generating evidence package…", total=None)
            pkg = generate_evidence_package(
                findings, employees, access, summary,
                output_dir=ROOT / "outputs" / "evidence",
            )
        console.print(f"[green][OK][/green] Evidence package saved: [cyan]{pkg}[/cyan]")

    if args.save_report:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = ROOT / "outputs" / "reports" / f"par_report_{ts}.html"
        build_html_report(findings, summary, report_path)
        console.print(f"[green][OK][/green] Executive report saved: [cyan]{report_path}[/cyan]")

    console.print()
    console.print(Panel(
        "[bold yellow]Next Steps:[/bold yellow]\n"
        "• Run [cyan]python run_automation.py --all[/cyan] to save evidence packages & reports\n"
        "• Run [cyan]streamlit run dashboard/app.py[/cyan] to open the interactive dashboard\n"
        "• Critical findings require remediation within 24–48 hours per SLA",
        border_style="yellow", padding=(0, 2),
    ))
    console.print()


if __name__ == "__main__":
    main()
