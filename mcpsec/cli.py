import argparse
import json
from pathlib import Path
import yaml
from mcpsec.report.render_md import render_markdown
from mcpsec.agents.probe_agent import ProbeAgent, ProbeAgentConfig
from mcpsec.agents.policy_agent import PolicyAgent, PolicyAgentConfig
from mcpsec.patch.apply import apply_patch_plan_to_config, load_json, save_json
import os

def infer_caps_from_name_and_pkg(name, pkg, transport):
    caps = set()
    s = ((name or "") + " " + (pkg or "")).lower()

    # Repo tools
    if "git" in s or "github" in s:
        caps.update(["repo.read", "repo.write"])

    # Filesystem / DB tools
    if "file" in s or "filesystem" in s:
        caps.update(["fs.read", "fs.write"])
    if "sqlite" in s or "db" in s:
        caps.update(["db.read", "db.write"])

    # Remote
    if transport == "http":
        caps.add("remote.call")

    return list(caps)



def compute_findings(config: dict, replay: bool = False) -> dict:
    from mcpsec.intel.osv import query_osv_package
    from mcpsec.intel.github_adv import search_github_advisories
    from mcpsec.intel.nvd import search_nvd_cves

    servers = config.get("servers", [])
    findings = []
    score = 0
    intel = {"osv": []}
    has_repo_write = False
    has_fs_write = False
    has_remote = False
    
    intel_summary = {
    "osv_queries": 0, "osv_hits": 0,
    "ghsa_queries": 0, "ghsa_hits": 0,
    "nvd_queries": 0, "nvd_hits": 0,
        }
    probes = {}
    probe_agent = None

    if os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_PAT"):
        probe_agent = ProbeAgent(ProbeAgentConfig(probes_per_server=7))
    
    policy = None
    policy_agent = None

    if os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_PAT"):
        policy_agent = PolicyAgent(PolicyAgentConfig())
        
    for s in servers:
        name = s.get("name", "unknown")
        pkg = s.get("package")
        version = s.get("version", "unknown")
        auth_required = (s.get("auth") or {}).get("required", False)
        transport = s.get("transport")
        caps = s.get("capabilities", []) or []

        if not caps:
            inferred = infer_caps_from_name_and_pkg(name, pkg, transport)
            s["capabilities"] = inferred
            caps = inferred  # ✅ IMPORTANT: refresh local caps

        
        if "repo.write" in caps:
            has_repo_write = True
        if "fs.write" in caps or "db.write" in caps:
            has_fs_write = True
        if transport == "http":
            has_remote = True

        if probe_agent:
            try:
                probes[name] = probe_agent.generate_injection_probes({
                    "name": name,
                    "package": pkg,
                    "version": version,
                    "transport": transport,
                    "capabilities": caps,
            # you can add schema later
           })
            except Exception as e:
                probes[name] = [f"PROBE_ERR: {str(e)}"]    
        # -------------------------
        # Policy checks (same as before)
        # -------------------------
        has_write = any(c.endswith(".write") for c in caps)
        has_read  = any(c.endswith(".read")  for c in caps)

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
            intel_summary["osv_queries"] += 1
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
                    intel_summary["osv_hits"] += 1 
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
        if pkg:
            intel_summary["ghsa_queries"] += 1
            try:
                ghsa_data = search_github_advisories(
                query=pkg,
                cache_dir="data/cache/ghsa",
                replay=replay,
                token=None,  # optional: you can add GITHUB_TOKEN later
            
                )   

                raw = ghsa_data if isinstance(ghsa_data, list) else []
                filtered = []
                pkg_l = pkg.lower()

                for a in raw:
                    text = ((a.get("summary") or "") + " " + (a.get("description") or "")).lower()
                    if pkg_l in text:
                        filtered.append(a)

                hit_count = len(filtered)
                hits = [(a.get("ghsa_id") or a.get("id")) for a in filtered][:20]


                if hit_count > 0:
                    intel_summary["ghsa_hits"] += 1
                    findings.append({
                        "server": name,
                        "severity": "HIGH",
                        "rule_id": "GHSA_001",
                        "title": "GitHub Security Advisories found for package",
                        "evidence": {"package": pkg, "ghsa_ids": hits},
                        "recommendation": "Review GitHub advisories; upgrade or mitigate affected versions."
                    })
                    score += 30

            except Exception as e:
                findings.append({
                    "server": name,
                    "severity": "LOW",
                    "rule_id": "GHSA_ERR",
                    "title": "GitHub advisory lookup failed",
                    "evidence": {"package": pkg, "error": str(e)},
                    "recommendation": "Check network or add a GitHub token if rate-limited."
                })   


        if pkg:
            intel_summary["nvd_queries"] += 1
            try:
                nvd_data = search_nvd_cves(
                keyword=pkg,
                cache_dir="data/cache/nvd",
                replay=replay,
                api_key=None,  # optional: add NVD API key later for higher rate limits
               )

                vulns = nvd_data.get("vulnerabilities", [])
                cve_ids = []
                for v in vulns:
                    cve = v.get("cve", {})
                    cid = cve.get("id")
                    if cid:
                        cve_ids.append(cid)

                if len(cve_ids) > 0:
                    intel_summary["nvd_hits"] += 1  
                    findings.append({
                        "server": name,
                        "severity": "HIGH",
                        "rule_id": "NVD_001",
                        "title": "NVD reports CVEs matching this package",
                        "evidence": {"package": pkg, "cve_ids": cve_ids[:20]},
                        "recommendation": "Review CVEs in NVD; patch, upgrade, or mitigate affected components."
                    })
                    score += 30

            except Exception as e:
                findings.append({
                    "server": name,
                    "severity": "LOW",
                    "rule_id": "NVD_ERR",
                    "title": "NVD lookup failed",
                    "evidence": {"package": pkg, "error": str(e)},
                    "recommendation": "Check network or add an NVD API key to avoid rate limits."
                })        

    if has_repo_write and has_fs_write and has_remote:
        findings.append({
            "server": "*project*",
            "severity": "HIGH",
            "rule_id": "CHAIN_001",
            "title": "High-risk toolchain combination (repo write + fs/db write + remote)",
            "evidence": {
                "has_repo_write": has_repo_write,
                "has_fs_or_db_write": has_fs_write,
                "has_remote": has_remote
            },
            "recommendation": "Apply least-privilege: split tools, require human approval for writes, sandbox FS/DB, and isolate remote tools."
        })
        score += 50
    if policy_agent:
        try:
            policy = policy_agent.generate_mitigations(
                project=config.get("project", "unknown"),
                servers=servers,
                findings=findings,
                probes=probes if isinstance(probes, dict) else None,
           )
        except Exception as e:
            policy = {"error": str(e)}


    score = min(100, score)

    
    return {
        "project": config.get("project", "unknown"),
        "servers_scanned": len(servers),
        "risk_score": score,
        "findings": findings,
        "intel": intel,
        "intel_summary": intel_summary,
        "probes": probes,
        "policy": policy,
        "replay": replay,
    }

def main():
    parser = argparse.ArgumentParser(description="MCP Toolchain Security Gatekeeper")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("--config", default="gatekeeper.yaml", help="Path to config file")
    parser.add_argument("--out", default="out", help="Output folder")
    parser.add_argument("--replay", action="store_true", help="Use cached API responses only (no network).")
    parser.add_argument("--format",default="auto",choices=["auto", "gatekeeper", "vscode", "mcpservers"],help="Config format (auto-detect, gatekeeper, vscode, mcpservers)")
    parser.add_argument("--apply", action="store_true", help="Apply policy.patch_plan to config and write a hardened config JSON.")
    parser.add_argument("--apply-out", default=None, help="Output path for hardened config (default: <out>/hardened_config.json)")
    parser.add_argument("--report-json", default=None, help="If provided, use this existing report.json as source of policy.patch_plan (skip rescanning).")

    args = parser.parse_args()

    if args.command == "scan":
        print("MCPSEC: scan started")
        print("Using config:", args.config)
        
        if args.format == "auto":
            raw = json.loads(Path(args.config).read_text(encoding="utf-8"))
            if "mcpServers" in raw:
                from mcpsec.adapters.mcpservers import load_mcpservers_config
                config = load_mcpservers_config(args.config)
            elif "servers" in raw:
                from mcpsec.adapters.vscode import load_vscode_config
                config = load_vscode_config(args.config)
            else:
                with open(args.config, "r") as f:
                    config = yaml.safe_load(f)

        elif args.format == "vscode":
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
        
        
        if args.apply:
    # Source patch plan from current run OR from --report-json
            if args.report_json:
                prev = load_json(args.report_json)
                patch_plan = ((prev.get("policy") or {}).get("patch_plan")) or []
            else:
                patch_plan = ((report.get("policy") or {}).get("patch_plan")) or []

    # Load raw config JSON (apply mode supports JSON configs: mcpServers / servers)
            raw_cfg = load_json(args.config)

            hardened = apply_patch_plan_to_config(raw_cfg, patch_plan)

            apply_out = args.apply_out or f"{args.out}/hardened_config.json"
            save_json(apply_out, hardened)
            print(f"Wrote hardened config: {apply_out}")

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
