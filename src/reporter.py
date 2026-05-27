"""Terminal + CSV + markdown reporting for ROSI-scored security findings."""

from __future__ import annotations

import csv
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from tabulate import tabulate

OUTPUT_DIR = Path("output")
CSV_PATH = OUTPUT_DIR / "ranked_remediation_backlog.csv"
MD_PATH = OUTPUT_DIR / "executive_summary.md"

_CSV_COLUMNS = [
    "rank",
    "finding_id",
    "raw_description",
    "source_tool",
    "date_found",
    "assigned_to",
    "risk_domain",
    "severity",
    "threat_frequency",
    "vulnerability_probability",
    "asset_value_usd",
    "control_effectiveness",
    "estimated_remediation_cost_usd",
    "risk_reduction_pct",
    "ale",
    "residual_ale",
    "financial_benefit",
    "rosi",
    "priority_tier",
    "recommended_action",
    "normalization_rationale",
]

_TIER_TARGET_DAYS = {
    "TIER 1 — IMMEDIATE": 2,
    "TIER 2 — HIGH PRIORITY": 14,
    "TIER 3 — STANDARD": 90,
    "TIER 4 — MONITOR": 180,
    "TIER 5 — DEPRIORITIZE": 365,
}


def _fmt_usd(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"${value:,.0f}"


def _fmt_rosi(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}x"


def _target_date(tier: str | None) -> str:
    days = _TIER_TARGET_DAYS.get(tier or "", 90)
    return (date.today() + timedelta(days=days)).isoformat()


def generate_report(scored_issues: list[dict[str, Any]]) -> None:
    """Render ROSI-scored findings to terminal, CSV, and executive markdown.

    Sorts by ROSI desc, prints a tabulated terminal view + portfolio summary,
    writes the full backlog to output/ranked_remediation_backlog.csv, and
    writes a stakeholder-facing markdown report to output/executive_summary.md.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    scorable = [i for i in scored_issues if i.get("rosi") is not None]
    unscorable = [i for i in scored_issues if i.get("rosi") is None]

    ranked = sorted(scorable, key=lambda i: i["rosi"], reverse=True)
    for idx, issue in enumerate(ranked, start=1):
        issue["rank"] = idx

    _print_terminal_table(ranked)
    _print_portfolio_summary(ranked, unscorable)
    _write_csv(ranked + unscorable)
    _write_markdown(ranked)

    print(f"\nWrote {CSV_PATH} and {MD_PATH}")


def _print_terminal_table(ranked: list[dict[str, Any]]) -> None:
    rows = [
        [
            issue["rank"],
            issue.get("finding_id", "—"),
            issue.get("risk_domain", "—"),
            issue.get("severity", "—"),
            _fmt_usd(issue.get("ale")),
            _fmt_usd(issue.get("estimated_remediation_cost_usd")),
            _fmt_rosi(issue.get("rosi")),
            issue.get("priority_tier", "—"),
        ]
        for issue in ranked
    ]
    headers = [
        "Rank",
        "Finding ID",
        "Risk Domain",
        "Severity",
        "ALE ($)",
        "Remediation Cost ($)",
        "ROSI",
        "Priority Tier",
    ]
    print("\n=== Ranked Remediation Backlog ===\n")
    print(tabulate(rows, headers=headers, tablefmt="github"))


def _print_portfolio_summary(
    ranked: list[dict[str, Any]],
    unscorable: list[dict[str, Any]],
) -> None:
    total = len(ranked) + len(unscorable)
    total_ale = sum(i["ale"] for i in ranked)
    total_remediation = sum(
        i["estimated_remediation_cost_usd"]
        for i in ranked
        if i.get("estimated_remediation_cost_usd") is not None
    )
    avg_rosi = sum(i["rosi"] for i in ranked) / len(ranked) if ranked else 0.0
    top5 = ranked[:5]
    top5_ale_reduction = sum(i["ale"] - i["residual_ale"] for i in top5)

    print("\n=== Portfolio Summary ===\n")
    print(f"Total issues:                       {total}")
    if unscorable:
        print(f"  (scored: {len(ranked)}, unscorable: {len(unscorable)})")
    print(f"Total portfolio ALE:                {_fmt_usd(total_ale)}")
    print(f"Total remediation budget needed:    {_fmt_usd(total_remediation)}")
    print(f"Average ROSI:                       {_fmt_rosi(avg_rosi)}")
    print(f"Est. ALE reduction if top 5 fixed:  {_fmt_usd(top5_ale_reduction)}")


def _write_csv(all_issues: list[dict[str, Any]]) -> None:
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for issue in all_issues:
            writer.writerow({col: issue.get(col, "") for col in _CSV_COLUMNS})


def _write_markdown(ranked: list[dict[str, Any]]) -> None:
    total_ale = sum(i["ale"] for i in ranked)
    total_remediation = sum(
        i["estimated_remediation_cost_usd"]
        for i in ranked
        if i.get("estimated_remediation_cost_usd") is not None
    )
    avg_rosi = sum(i["rosi"] for i in ranked) / len(ranked) if ranked else 0.0
    top5 = ranked[:5]
    top5_ale_reduction = sum(i["ale"] - i["residual_ale"] for i in top5)
    top5_cost = sum(
        i.get("estimated_remediation_cost_usd") or 0 for i in top5
    )

    lines: list[str] = []
    lines.append("# Executive Summary — Security Remediation Backlog")
    lines.append("")
    lines.append(f"_Generated {date.today().isoformat()}_")
    lines.append("")
    lines.append("## Portfolio overview")
    lines.append("")
    lines.append(
        f"Across **{len(ranked)} scored findings**, the portfolio carries an estimated "
        f"**{_fmt_usd(total_ale)}** in annualized loss expectancy (ALE). Fully remediating "
        f"the backlog would cost roughly **{_fmt_usd(total_remediation)}** at an average "
        f"ROSI of **{_fmt_rosi(avg_rosi)}**. Concentrating effort on the top 5 issues "
        f"would cost **{_fmt_usd(top5_cost)}** and is estimated to avoid "
        f"**{_fmt_usd(top5_ale_reduction)}** of annualized loss — the bulk of the "
        f"available risk reduction."
    )
    lines.append("")

    lines.append("## Top 5 by ROSI")
    lines.append("")
    lines.append("| Rank | Finding ID | Risk Domain | Severity | ALE | Remediation Cost | ROSI | Priority Tier |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for issue in top5:
        lines.append(
            f"| {issue['rank']} "
            f"| {issue.get('finding_id', '—')} "
            f"| {issue.get('risk_domain', '—')} "
            f"| {issue.get('severity', '—')} "
            f"| {_fmt_usd(issue.get('ale'))} "
            f"| {_fmt_usd(issue.get('estimated_remediation_cost_usd'))} "
            f"| {_fmt_rosi(issue.get('rosi'))} "
            f"| {issue.get('priority_tier', '—')} |"
        )
    lines.append("")

    lines.append("## Recommended sprint plan")
    lines.append("")
    lines.append("| Finding ID | Owner | Target Date | Action |")
    lines.append("|---|---|---|---|")
    for issue in top5:
        owner = issue.get("assigned_to") or "<assign owner>"
        target = _target_date(issue.get("priority_tier"))
        action = issue.get("recommended_action", "—")
        lines.append(
            f"| {issue.get('finding_id', '—')} | {owner} | {target} | {action} |"
        )
    lines.append("")

    MD_PATH.write_text("\n".join(lines), encoding="utf-8")
