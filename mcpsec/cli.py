import argparse
import json
from pathlib import Path
import yaml
from mcpsec.report.render_md import render_markdown

def compute_findings(config: dict, replay: bool = False) -> dict:
    from mcpsec.intel.osv import query_osv_package

    servers = config.get("servers", [])
    findings = []
    score = 0
    intel = {"osv": []}

    for s in servers:
        name = s.get("name", "unknown")
        pkg = s.get("package")
        version = s.get("version", "unknown")
        auth_required = (s.get("auth") or {}).get("required", False)
        caps = s.get("capabilities", [])

        # -------------------------
        # Policy checks (same as before)
        # -------------------------
        has_write = any("write" in c for c in caps)
        has_read = any("read" in c for c in caps)

        if not auth_required and has_write:
            findings.append({
                "server": name,
                "severity": "HIGH",
                "rule_id": "AUTH_001",
                "title": "Write capability without authentication",
                "evidence": {"capabilities": caps, "auth_required": auth_required},
                "recommendation": "Require auth for this server OR remove write capabilities."
            })
            score += 40

        if has_read and has_write:
            findings.append({
                "server": name,
                "severity": "MEDIUM",
                "rule_id": "SCOPE_001",
                "title": "Broad scope (read + write)",
                "evidence": {"capabilities": caps},
                "recommendation": "Split into separate servers or reduce permissions to least-privilege."
            })
            score += 15
            
        transport = s.get("transport")
        is_remote = (transport == "http") or bool(s.get("url"))
        
        if (not is_remote) and (not pkg):
            findings.append({
                "server": name,
                "severity": "LOW",
                "rule_id": "META_001",
                "title": "Missing package metadata for local server",
                "evidence": {"package": pkg, "command": s.get("command"), "args": s.get("args")},
                "recommendation": "Add/derive package name (e.g., npx package) so vulnerability intel matching can work."
            })
            score += 5
        if is_remote:
            header_keys = s.get("header_keys", []) or []
            secret_header_keys = s.get("secret_header_keys", []) or []
            auth_required = (s.get("auth") or {}).get("required", False)
        
            if not auth_required:
                findings.append({
                    "server": name,
                    "severity": "HIGH",
                    "rule_id": "REMOTE_AUTH_001",
                    "title": "Remote MCP server without authentication signal",
                    "evidence": {"url": s.get("url"), "header_keys": header_keys},
                    "recommendation": "Require auth (e.g., Authorization header / OAuth) and restrict server access by default."
                })
                score += 40
            
            if secret_header_keys:
                findings.append({
                    "server": name,
                    "severity": "MEDIUM",
                    "rule_id": "REMOTE_SECRET_001",
                    "title": "Remote MCP server uses sensitive headers (handle secrets safely)",
                    "evidence": {"url": s.get("url"), "sensitive_header_keys": secret_header_keys},
                    "recommendation": "Store secrets in a secure manager, rotate regularly, and never log header values."
                })
                score += 10
        
        
        # -------------------------
        # OSV lookup (real world)
        # -------------------------
        if pkg and (version in (None, "", "unknown")):
            findings.append({
                "server": name,
                "severity": "MEDIUM",
                "rule_id": "PIN_001",
                "title": "Unpinned server version (supply-chain risk)",
                "evidence": {"package": pkg, "version": version},
                "recommendation": "Pin an explicit version (e.g., pkg@1.2.3) to make scans reproducible and reduce supply-chain risk."
            })
            score += 10
        
        
        if pkg and (not is_remote):
            try:
                osv_data = query_osv_package(
                    package_name=pkg,
                    ecosystem=s.get("ecosystem"),
                    version=s.get("version"),           # keep None for best-effort tonight
                    cache_dir="data/cache/osv",
                    replay=replay,
                )

                vulns = osv_data.get("vulns", [])
                intel["osv"].append({
                    "server": name,
                    "package": pkg,
                    "vuln_count": len(vulns),
                    "vuln_ids": [v.get("id") for v in vulns][:20],
                })

                # Simple scoring: any vuln IDs -> add risk
                if len(vulns) > 0:
                    findings.append({
                        "server": name,
                        "severity": "HIGH",
                        "rule_id": "OSV_001",
                        "title": "OSV reports known vulnerabilities for package",
                        "evidence": {"package": pkg, "vuln_ids": [v.get("id") for v in vulns][:20]},
                        "recommendation": "Review advisories; pin/upgrade to a non-vulnerable version if possible."
                    })
                    score += 30

            except Exception as e:
                findings.append({
                    "server": name,
                    "severity": "LOW",
                    "rule_id": "OSV_ERR",
                    "title": "OSV lookup failed",
                    "evidence": {"package": pkg, "error": str(e)},
                    "recommendation": "Check network / package name / retry with replay disabled."
                })

    score = min(100, score)

    return {
        "project": config.get("project", "unknown"),
        "servers_scanned": len(servers),
        "risk_score": score,
        "findings": findings,
        "intel": intel,
        "replay": replay,
    }

def main():
    parser = argparse.ArgumentParser(description="MCP Toolchain Security Gatekeeper")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("--config", default="gatekeeper.yaml", help="Path to config file")
    parser.add_argument("--out", default="out", help="Output folder")
    parser.add_argument("--replay", action="store_true", help="Use cached API responses only (no network).")
    parser.add_argument("--format", default="gatekeeper", choices=["gatekeeper", "vscode", "mcpservers"], help="Config format")
    
    args = parser.parse_args()

    if args.command == "scan":
        print("MCPSEC: scan started")
        print("Using config:", args.config)

        if args.format == "vscode":
            from mcpsec.adapters.vscode import load_vscode_config
            config = load_vscode_config(args.config)
        elif args.format == "mcpservers":
            from mcpsec.adapters.mcpservers import load_mcpservers_config
            config = load_mcpservers_config(args.config)
        else:
            with open(args.config, "r") as f:
                config = yaml.safe_load(f)

        report = compute_findings(config, replay=args.replay)

        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "report.json"

        md_path = out_dir / "report.md"
        md_path.write_text(render_markdown(report), encoding="utf-8")
        print("Wrote:", md_path)
        
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        print("\nSummary:")
        print("- Project:", report["project"])
        print("- Servers scanned:", report["servers_scanned"])
        print("- Risk score:", report["risk_score"])
        print("- Findings:", len(report["findings"]))
        print("\nWrote:", out_path)

        # Print findings nicely
        for f in report["findings"]:
            print(f'  [{f["severity"]}] {f["server"]}: {f["title"]} ({f["rule_id"]})')

        print("\nScan finished ✅")

if __name__ == "__main__":
    main()
