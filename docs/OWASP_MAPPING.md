# OWASP LLM Top 10 Mapping

This document maps MCP Toolchain Security Gatekeeper findings and agents to the OWASP LLM Top 10 risk categories.

---

## LLM01: Prompt Injection

**Covered by:**
- ProbeAgent (LLM-generated adversarial probes)
- CHAIN_001 (dangerous toolchain combinations)
- Tool-specific misuse probes (fs, db, repo, remote)

**How:**
The ProbeAgent generates adversarial prompts tailored to each MCP tool’s capabilities (read/write, repo, db, fs, remote).  
This simulates real-world prompt injection and tool misuse attempts.

---

## LLM02: Insecure Output Handling

**Covered by:**
- PolicyAgent remediation guidance
- “Apply” mode safeguards (human review before deployment)

**How:**
The PolicyAgent produces structured, reviewable patch plans instead of directly executing LLM output.  
This reduces the risk of blindly trusting or applying unsafe model-generated actions.

---

## LLM05: Supply Chain Vulnerabilities

**Covered by:**
- OSV_001 findings (OSV database)
- GHSA_001 findings (GitHub Security Advisories)
- NVD CVE lookups

**How:**
The scanner correlates MCP server packages against:
- OSV
- GitHub Security Advisories
- NVD (CVE)

Any known vulnerabilities raise findings and increase risk score.

---

## LLM06: Over-Privileged Tools

**Covered by:**
- AUTH_001 (write without authentication)
- SCOPE_001 (read + write in same tool)
- CHAIN_001 (dangerous capability combinations)

**How:**
The engine flags tools that:
- Have write access without auth
- Combine read + write unnecessarily
- Form high-risk chains (e.g., repo write + fs/db write + remote)

---

## LLM07: Insecure Plugin / Tool Use

**Covered by:**
- Capability inference + validation
- PolicyAgent hardening recommendations
- Apply mode (tool splitting, auth enforcement)

**How:**
The system treats MCP servers as high-risk tools and enforces:
- Least privilege
- Explicit authentication
- Capability separation

---

## LLM10: Model Overreliance

**Covered by:**
- Deterministic core (inventory, parsing, vuln intel)
- LLM used only for probes and policy reasoning
- Human-in-the-loop review for hardened configs

**How:**
Security-critical parsing and scoring are deterministic and auditable.  
LLMs are only used where generative reasoning is needed (attack simulation, remediation drafting).

---

## Summary

MCP Toolchain Security Gatekeeper combines:
- Deterministic security analysis (safe, auditable)
- LLM-based reasoning (probes + remediation)
- Policy enforcement and measurable risk reduction

This directly addresses multiple OWASP LLM Top 10 risk categories in a practical, toolchain-focused way.
