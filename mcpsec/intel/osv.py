import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

def _cache_key(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]

def query_osv_package(
    package_name: str,
    ecosystem: Optional[str] = None,
    version: Optional[str] = None,
    cache_dir: str = "data/cache/osv",
    replay: bool = False,
    timeout_s: int = 15,
) -> Dict[str, Any]:
    """
    OSV requires (name + ecosystem) OR purl.
    If version is provided, OSV returns vulns affecting that version.
    """
    if not ecosystem:
        # Without ecosystem, OSV returns 400 for name-based lookups
        return {"_error": "missing_ecosystem", "_hint": "Provide ecosystem like PyPI/npm/Go/Maven", "_package": package_name}

    payload: Dict[str, Any] = {"package": {"name": package_name, "ecosystem": ecosystem}}
    if version and version not in ("unknown", ""):
        payload["version"] = version

    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    key = _cache_key(payload)
    file_path = cache_path / f"{key}.json"

    if file_path.exists():
        return json.loads(file_path.read_text(encoding="utf-8"))

    if replay:
        # No cache available, but replay requested
        return {"_error": "replay_enabled_but_cache_missing", "_payload": payload}

    # Network call
    resp = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()

    # Save to cache
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data