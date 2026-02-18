from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional


def _find_pkg_arg_index(args: List[str]) -> Optional[int]:
    """
    Heuristic for npx-style args:
      ["-y", "<package>"]  -> pkg index 1
      ["-y", "<package>", ...] -> pkg index 1
    """
    if not args:
        return None
    # Prefer the first arg that looks like a package name (not a flag)
    for i, a in enumerate(args):
        if a.startswith("-"):
            continue
        # crude package-ish check
        if "/" in a or a.startswith("@") or re.match(r"^[a-zA-Z0-9][\w\-]*$", a):
            return i
    return None


def _pin_pkg_in_args(args: List[str], pkg: str, version: str) -> List[str]:
    new_args = list(args or [])
    i = _find_pkg_arg_index(new_args)
    if i is None:
        return new_args
    # Replace existing pkg token with pinned pkg@version
    base = pkg.split("@")[0] if pkg.startswith("@") is False else pkg  # keep scoped names as-is
    # If already scoped like @scope/name@x, we still want @scope/name@version
    if pkg.startswith("@") and "@" in pkg[1:]:
        base = pkg.rsplit("@", 1)[0]
    pinned = f"{base}@{version}"
    new_args[i] = pinned
    return new_args


def apply_patch_plan_to_config(raw_config: Dict[str, Any], patch_plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Applies patch_plan to a JSON config that is either:
      - MCPServers style: {"mcpServers": {...}}
      - VSCode style: {"servers": {...}}
    Returns a NEW dict (does not mutate input).
    """
    cfg = copy.deepcopy(raw_config)

    if "mcpServers" in cfg:
        root_key = "mcpServers"
    elif "servers" in cfg:
        root_key = "servers"
    else:
        # unknown shape; no-op
        return cfg

    servers = cfg.get(root_key, {})
    if not isinstance(servers, dict):
        return cfg

    for act in (patch_plan or []):
        op = act.get("op")
        server = act.get("server")

        if op == "set_auth_required":
            if server in servers and isinstance(servers[server], dict):
                servers[server].setdefault("auth", {})
                if not isinstance(servers[server]["auth"], dict):
                    servers[server]["auth"] = {}
                servers[server]["auth"]["required"] = bool(act.get("value", True))

        elif op == "reduce_capabilities":
            # This is "mcpsec metadata" (clients may ignore), but your scanner will read it.
            if server in servers and isinstance(servers[server], dict):
                caps = servers[server].get("capabilities") or []
                if not isinstance(caps, list):
                    caps = []
                remove = set(act.get("remove") or [])
                add = act.get("add") or []
                caps = [c for c in caps if c not in remove]
                for c in add:
                    if c not in caps:
                        caps.append(c)
                servers[server]["capabilities"] = caps

        elif op == "split_server":
            if server not in servers or not isinstance(servers[server], dict):
                continue
            base = servers[server]
            into = act.get("into") or []
            if not isinstance(into, list) or not into:
                continue

            # Remove original
            servers.pop(server, None)

            # Add split servers inheriting command/args/env/url/headers
            for part in into:
                new_name = part.get("name")
                if not new_name:
                    continue
                new_entry = copy.deepcopy(base)
                # attach capabilities metadata for scanner + future policy
                if part.get("capabilities"):
                    new_entry["capabilities"] = list(part["capabilities"])
                servers[new_name] = new_entry

        elif op == "pin_version":
            if server in servers and isinstance(servers[server], dict):
                pkg = act.get("package")
                ver = act.get("version")
                if not (pkg and ver):
                    continue
                entry = servers[server]
                args = entry.get("args") or []
                if isinstance(args, list):
                    entry["args"] = _pin_pkg_in_args(args, pkg, ver)

        elif op == "add_allowlist":
            # store allowlists as metadata
            if server in servers and isinstance(servers[server], dict):
                kind = act.get("kind", "path")
                allow = act.get("allow") or []
                servers[server].setdefault("mcpsec_allowlist", {})
                servers[server]["mcpsec_allowlist"][kind] = allow

        # unknown ops -> ignore (safe default)

    cfg[root_key] = servers
    return cfg


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")