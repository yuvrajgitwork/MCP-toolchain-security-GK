from datetime import datetime
from typing import Dict, Any, List

def _sev_rank(sev: str) -> int:
    return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)

def render_markdown(report: Dict[str, Any]) -> str:
    findings: List[Dict[str, Any]] = report.get("findings", [])
    findings_sorted = sorted(findings, key=lambda f: _sev_rank(f.get("severity","")), reverse=True)

    lines = []
    lines.append(f"# MCP Toolchain Security Gatekeeper Report\n")
    lines.append(f"- **Project:** {report.get('project')}")
    lines.append(f"- **Servers scanned:** {report.get('servers_scanned')}")
    lines.append(f"- **Risk score:** {report.get('risk_score')}/100")
    lines.append(f"- **Replay mode:** {report.get('replay')}")
    lines.append(f"- **Generated:** {datetime.utcnow().isoformat()}Z\n")

    # Summary counts
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.get("severity","LOW")] = counts.get(f.get("severity","LOW"), 0) + 1

    lines.append("## Summary\n")
    lines.append(f"- HIGH: **{counts.get('HIGH',0)}**")
    lines.append(f"- MEDIUM: **{counts.get('MEDIUM',0)}**")
    lines.append(f"- LOW: **{counts.get('LOW',0)}**\n")

    # Findings table
    lines.append("## Findings\n")
    lines.append("| Severity | Server | Rule | Title |")
    lines.append("|---|---|---|---|")
    for f in findings_sorted:
        lines.append(f"| {f.get('severity')} | {f.get('server')} | {f.get('rule_id')} | {f.get('title')} |")
    lines.append("")

    # Detailed findings
    lines.append("## Details\n")
    for f in findings_sorted:
        lines.append(f"### [{f.get('severity')}] {f.get('server')} — {f.get('title')}")
        lines.append(f"- **Rule:** `{f.get('rule_id')}`")
        lines.append(f"- **Evidence:** `{f.get('evidence')}`")
        lines.append(f"- **Recommendation:** {f.get('recommendation')}\n")

    # Intel section
    lines.append("## Vulnerability Intelligence\n")
    osv = (report.get("intel") or {}).get("osv", [])
    if not osv:
        lines.append("- OSV: (no results)\n")
    else:
        lines.append("| Server | Package | Vulns | IDs (first 20) |")
        lines.append("|---|---|---:|---|")
        for row in osv:
            ids = ", ".join([i for i in (row.get("vuln_ids") or []) if i])
            lines.append(f"| {row.get('server')} | {row.get('package')} | {row.get('vuln_count')} | {ids} |")
        lines.append("")

    return "\n".join(lines)
