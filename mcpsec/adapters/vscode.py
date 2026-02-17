import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple



def infer_npx_package_and_version(args: list) -> Tuple[Optional[str], Optional[str]]:
    """
    Finds the first non-flag arg that looks like a package.
    Supports scoped packages and optional @version:
      @scope/name@1.2.3  -> package=@scope/name, version=1.2.3
      name@1.2.3         -> package=name, version=1.2.3
      @scope/name        -> package=@scope/name, version=None
      name               -> package=name, version=None
    """
    pkg_token = None
    for a in args:
        if isinstance(a, str) and not a.startswith("-"):
            pkg_token = a
            break
    if not pkg_token:
        return None, None

    # Scoped package with optional version: @scope/name@1.2.3
    if pkg_token.startswith("@"):
        # split into ["", "scope/name", "1.2.3"] or ["", "scope/name"]
        parts = pkg_token.split("@")
        if len(parts) >= 3:
            pkg = "@" + parts[1]
            ver = parts[2] if parts[2] else None
            return pkg, ver
        return pkg_token, None

    # Unscoped with optional version: name@1.2.3
    if "@" in pkg_token:
        pkg, ver = pkg_token.rsplit("@", 1)
        return pkg, (ver or None)

    return pkg_token, None


def infer_package_version_ecosystem(command: str | None, args: list):
    if not command:
        return None, None, None
    cmd = command.lower()

    if cmd == "npx":
        pkg, ver = infer_npx_package_and_version(args)
        eco = "npm" if pkg else None
        return pkg, ver, eco

    if cmd == "uvx":
        # uvx mcp-server-sqlite==0.1.2 (if present), else unpinned
        # We'll keep it simple for tonight:
        for a in args:
            if isinstance(a, str) and not a.startswith("-"):
                token = a
                break
        else:
            return None, None, None

        if "==" in token:
            pkg, ver = token.split("==", 1)
            return pkg, ver, "PyPI"
        return token, None, "PyPI"

    return None, None, None

def load_vscode_config(path: str) -> Dict[str, Any]:
    """
    Reads a VS Code-style MCP config:
    {
      "servers": {
        "name": {
          "type": "stdio" | "http",
          "command": "...",
          "args": [...],
          "env": {...}
        }
      }
    }
    Normalizes to:
    {
      "project": "<filename>",
      "servers": [ { name, command, args, env_keys, transport, package?, version? } ]
    }
    """
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))

    servers_in = raw.get("servers", {})
    servers_out: List[Dict[str, Any]] = []

    for name, cfg in servers_in.items():
        transport = cfg.get("type", "stdio")
        command = cfg.get("command")
        args = cfg.get("args", [])
        pkg, ver, eco = infer_package_version_ecosystem(command, args)
        env = cfg.get("env", {}) or {}

        # Redact env values: keep keys only
        env_keys = list(env.keys())

        servers_out.append({
            "name": name,
            "transport": transport,
            "command": command,
            "args": args,
            "env_keys": env_keys,
            # Best-effort fields for intel (may be None)
            "package": pkg,
            "version": ver if ver else "un-pinned",
            "ecosystem": eco,
            # Capabilities unknown at this stage; leave empty
            "capabilities": [],
            # Auth unknown; infer later
            "auth": {"required": False}
        })

    return {
        "project": p.name,
        "servers": servers_out
    }
