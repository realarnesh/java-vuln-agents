import json

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def to_json(report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(report) -> str:
    m = report.metrics
    out = ["# Java Vulnerability Report", ""]
    out.append(
        f"Scanned **{m['files']} files** in **{m['chunks']} bounded tasks** "
        f"({m['chunks_skipped']} skipped with no security signals) using the `{m['provider']}` provider."
    )
    out.append(
        f"Context sent to the scanner: {m['tokens_sent']} of {m['tokens_raw']} estimated tokens "
        f"({m['context_reduction_pct']}% reduction). Peak shared memory: {m['peak_memory_tokens']} tokens "
        f"(budget {m['memory_budget_tokens']})."
    )
    out += ["", f"## Findings ({len(report.findings)})", ""]
    if report.findings:
        out += ["| Severity | Rule | CWE | Location | Evidence |", "|---|---|---|---|---|"]
        for f in sorted(report.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line)):
            evidence = f.evidence.replace("|", "\\|")
            out.append(f"| {f.severity} | {f.rule_id} | {f.cwe} | `{f.file}:{f.line}` | `{evidence}` |")
    else:
        out.append("No vulnerabilities found.")
    if report.fixes:
        out += ["", "## Remediation", ""]
        for fx in report.fixes:
            if fx.status == "applied":
                out.append(f"- **Fixed** `{fx.file}:{fx.line}` ({fx.rule_id}): `{fx.original.strip()}` → `{fx.replacement.strip()}`")
            elif fx.status == "rejected":
                out.append(f"- **Fix rejected** `{fx.file}:{fx.line}` ({fx.rule_id}): {fx.note}")
            else:
                out.append(f"- **Manual** `{fx.file}:{fx.line}` ({fx.rule_id}): {fx.note}")
    if report.rejected:
        out += ["", f"## Rejected by validator ({len(report.rejected)})", ""]
        for r in report.rejected:
            out.append(f"- `{r.finding.get('rule_id')}` line {r.finding.get('line')}: {r.reason}")
    return "\n".join(out) + "\n"


def to_text(report) -> str:
    m = report.metrics
    lines = []
    for f in sorted(report.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line)):
        lines.append(f"[{f.severity.upper():6}] {f.rule_id:<11} {f.file}:{f.line}  {f.evidence}")
    lines.append("")
    lines.append(
        f"{m['findings']} findings in {m['files']} files | {m['chunks']} tasks ({m['chunks_skipped']} skipped) | "
        f"context {m['tokens_sent']}/{m['tokens_raw']} tokens (-{m['context_reduction_pct']}%) | "
        f"peak memory {m['peak_memory_tokens']}/{m['memory_budget_tokens']} | rejected {m['rejected']}"
    )
    if report.fixes:
        lines.append(f"fixes applied: {m['fixes_applied']} of {len(report.fixes)}")
    return "\n".join(lines)
