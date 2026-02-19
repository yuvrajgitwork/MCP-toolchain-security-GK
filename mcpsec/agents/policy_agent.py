from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

GITHUB_MODELS_CHAT_URL = "https://models.github.ai/inference/chat/completions"

SENSITIVE_KEYWORDS = (
    "token", "secret", "password", "authorization", "apikey", "api_key", "pat",
    "private_key", "cookie", "session", "bearer"
)

def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s in lk for s in SENSITIVE_KEYWORDS):
                out[k] = "REDACTED"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    if isinstance(obj, str):
        if len(obj) > 80 and re.search(r"[A-Za-z0-9_\-]{40,}", obj):
            return "REDACTED"
    return obj

def _extract_json_object(text: str) -> Dict[str, Any]:
    text = text.strip()
    # direct JSON
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    # extract first {...}
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

@dataclass
class PolicyAgentConfig:
    model: str = "openai/gpt-4o-mini"
    max_tokens: int = 1400
    temperature: float = 0.2
    timeout_s: int = 30

class PolicyAgent:
    """
    LLM remediation writer:
    Input: findings + normalized servers + (optional) probes summary
    Output: JSON with:
      - executive_summary (string)
      - prioritized_fixes (list)
      - patch_plan (list of machine-readable actions)
    """

    def __init__(self, cfg: Optional[PolicyAgentConfig] = None, token_env: str = "GITHUB_PAT"):
        self.cfg = cfg or PolicyAgentConfig()
        self.token = os.getenv(token_env) or os.getenv("MCPSEC_LLM_TOKEN") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_PAT")
        if not self.token:
            raise RuntimeError("PolicyAgent requires GITHUB_PAT (recommended) or GITHUB_TOKEN.")

    def generate_mitigations(
        self,
        project: str,
        servers: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        probes: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        safe_payload = _redact({
            "project": project,
            "servers": [
                {
                    "name": s.get("name"),
                    "package": s.get("package"),
                    "version": s.get("version"),
                    "transport": s.get("transport"),
                    "capabilities": s.get("capabilities", []),
                    "auth_required": (s.get("auth") or {}).get("required", False),
                    "url": s.get("url"),
                }
                for s in servers
            ],
            "findings": findings,
            # keep probes optional + trimmed
            "probes": {k: (v[:5] if isinstance(v, list) else v) for k, v in (probes or {}).items()},
        })

        system = (
            "You are a security engineer. Map findings to concrete MCP configuration mitigations.\n"
            "Return ONLY a JSON object with keys:\n"
            "  executive_summary: string (2-4 sentences)\n"
            "  prioritized_fixes: array of {severity, title, why_it_matters, exact_change}\n"
            "  patch_plan: array of actions, each action is one of:\n"
            "    {op:'set_auth_required', server:'name', value:true}\n"
            "    {op:'reduce_capabilities', server:'name', remove:['cap1'], add:['cap2']}\n"
            "    {op:'split_server', server:'name', into:[{name:'', capabilities:[]}, ...]}\n"
            "    {op:'pin_version', server:'name', package:'pkg', version:'x.y.z'}\n"
            "    {op:'add_allowlist', server:'name', kind:'path|repo', allow:['...']}\n"
            "Rules:\n"
            "- Be specific to the provided servers/capabilities.\n"
            "- Never include real secrets; use placeholders.\n"
            "- Prefer least privilege, human approval for writes, and isolation.\n"
        )

        user = (
            "Generate mitigations and a patch plan for this MCP toolchain scan:\n"
            f"{json.dumps(safe_payload, ensure_ascii=False)}\n"
            "Return JSON only."
        )

        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

        resp = requests.post(GITHUB_MODELS_CHAT_URL, headers=headers, json=payload, timeout=self.cfg.timeout_s)
        resp.raise_for_status()
        data = resp.json()
        content = ((data.get("choices") or [{}])[0].get("message", {}) or {}).get("content", "")

        out = _extract_json_object(content)
        if not out:
            # safe fallback
            out = {
                "executive_summary": "PolicyAgent could not parse model output. Use deterministic recommendations in findings.",
                "prioritized_fixes": [],
                "patch_plan": [],
            }
        return out