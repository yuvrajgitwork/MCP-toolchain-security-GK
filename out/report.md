# MCP Toolchain Security Gatekeeper Report

- **Project:** claude_cursor_mcp.json
- **Servers scanned:** 3
- **Risk score:** 10/100
- **Replay mode:** False
- **Generated:** 2026-02-16T23:55:30.671316Z

## Summary

- HIGH: **0**
- MEDIUM: **1**
- LOW: **0**

## Findings

| Severity | Server | Rule | Title |
|---|---|---|---|
| MEDIUM | github-remote | REMOTE_SECRET_001 | Remote MCP server uses sensitive headers (handle secrets safely) |

## Details

### [MEDIUM] github-remote — Remote MCP server uses sensitive headers (handle secrets safely)
- **Rule:** `REMOTE_SECRET_001`
- **Evidence:** `{'url': 'https://api.githubcopilot.com/mcp/', 'sensitive_header_keys': ['Authorization']}`
- **Recommendation:** Store secrets in a secure manager, rotate regularly, and never log header values.

## Vulnerability Intelligence

| Server | Package | Vulns | IDs (first 20) |
|---|---|---:|---|
| sqlite-explorer | mcp-server-sqlite | 0 |  |
| github | @modelcontextprotocol/server-github | 0 |  |
