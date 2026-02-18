import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def _looks_like_secret_key(k: str) -> bool:
    k2 = k.upper()
    return any(x in k2 for x in ["TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH", "COOKIE"])


def infer_npx_package_and_version(args: list) -> Tuple[Optional[str], Optional[str]]:
    # First non-flag arg
    pkg_token = None
    for a in args:
        if isinstance(a, str) and not a.startswith("-"):
            pkg_token = a
            break
    if not pkg_token:
        return None, None

    # Scoped: @scope/name@1.2.3
    if pkg_token.startswith("@"):
        parts = pkg_token.split("@")
        if len(parts) >= 3:
            pkg = "@" + parts[1]
            ver = parts[2] if parts[2] else None
            return pkg, ver
        return pkg_token, None

    # Unscoped: name@1.2.3
    if "@" in pkg_token:
        pkg, ver = pkg_token.rsplit("@", 1)
        return pkg, (ver or None)

    return pkg_token, None


def infer_package_version_ecosystem(command: Optional[str], args: list) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not command:
        return None, None, None
    cmd = command.lower()

    if cmd == "npx":
        pkg, ver = infer_npx_package_and_version(args)
        eco = "npm" if pkg else None
        return pkg, ver, eco

    if cmd == "uvx":
        # uvx mcp-server-sqlite==0.1.2 or uvx mcp-server-sqlite
        token = None
        for a in args:
            if isinstance(a, str) and not a.startswith("-"):
                token = a
                break
        if not token:
            return None, None, None
        if "==" in token:
            pkg, ver = token.split("==", 1)
            return pkg, ver, "PyPI"
        return token, None, "PyPI"

    # python server.py -> not a package we can OSV-scan by name
    return None, None, None


def load_mcpservers_config(path: str) -> Dict[str, Any]:
    """
    Reads Cursor/Claude-style MCP config:
    {
      "mcpServers": {
        "name": { "command": "...", "args": [...], "env": {...} },
        "remote": { "url": "...", "headers": {...} }
      }
    }

    Normalizes to:
    { "project": "<filename>", "servers": [ ... ] }
    """
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    servers_in = raw.get("mcpServers", {})

    servers_out: List[Dict[str, Any]] = []

    for name, cfg in servers_in.items():
        # Remote server
        if "url" in cfg:
            url = cfg.get("url")
            headers = cfg.get("headers", {}) or {}
            header_keys = list(headers.keys())
            secret_header_keys = [k for k in header_keys if _looks_like_secret_key(k)]

            # Infer "auth required" if Authorization-like headers exist
            auth_required = any(k.lower() in ("authorization", "cookie") for k in header_keys)

            servers_out.append({
                "name": name,
                "transport": "http",
                "url": url,
                "header_keys": header_keys,
                "secret_header_keys": secret_header_keys,
                "env_keys": [],
                "command": None,
                "args": [],
                "package": None,
                "version": None,
                "ecosystem": None,
                "capabilities": cfg.get("capabilities", []) or [],
                "auth": cfg.get("auth") or {"required": bool(auth_required)},
            })
            continue

        # Local stdio server
        command = cfg.get("command")
        args = cfg.get("args", []) or []
        env = cfg.get("env", {}) or {}
        env_keys = list(env.keys())
        secret_env_keys = [k for k in env_keys if _looks_like_secret_key(k)]

        pkg, ver, eco = infer_package_version_ecosystem(command, args)

        # If it uses secret-ish env keys, treat as auth required signal (best-effort)
        auth_required = len(secret_env_keys) > 0

        servers_out.append({
            "name": name,
            "transport": "stdio",
            "command": command,
            "args": args,
            "env_keys": env_keys,                 # values NOT stored
            "secret_env_keys": secret_env_keys,   # highlights risk
            "package": pkg,
            "version": ver if ver else ("un-pinned" if pkg else None),
            "ecosystem": eco,
            "capabilities": cfg.get("capabilities", []) or [],
            "auth": cfg.get("auth") or {"required": bool(auth_required)},
        })

    return {"project": p.name, "servers": servers_out}