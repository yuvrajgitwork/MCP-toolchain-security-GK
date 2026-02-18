import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional
import requests

GITHUB_ADVISORIES_SEARCH = "https://api.github.com/advisories"

def _cache_key(params: Dict[str, Any]) -> str:
    raw = json.dumps(params, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]

def search_github_advisories(
    query: str,
    cache_dir: str = "data/cache/ghsa",
    replay: bool = False,
    token: Optional[str] = None,
    timeout_s: int = 15,
) -> Dict[str, Any]:
    """
    Searches GitHub Global Security Advisories by keyword (package/repo name).
    Caches results for reproducibility.
    """
    params = {
        "per_page": 100,
        "page": 1,
        "q": query
    }

    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    key = _cache_key(params)
    file_path = cache_path / f"{key}.json"

    if file_path.exists():
        return json.loads(file_path.read_text(encoding="utf-8"))

    if replay:
        return {"_error": "replay_enabled_but_cache_missing", "_params": params}

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resp = requests.get(GITHUB_ADVISORIES_SEARCH, headers=headers, params=params, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()

    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data