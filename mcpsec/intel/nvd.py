import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional
import requests

NVD_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _cache_key(params: Dict[str, Any]) -> str:
    raw = json.dumps(params, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]

def search_nvd_cves(
    keyword: str,
    cache_dir: str = "data/cache/nvd",
    replay: bool = False,
    api_key: Optional[str] = None,
    timeout_s: int = 20,
) -> Dict[str, Any]:
    """
    Searches NVD CVEs by keyword.
    Caches results for reproducibility.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    }

    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)

    key = _cache_key(params)
    file_path = cache_path / f"{key}.json"

    if file_path.exists():
        return json.loads(file_path.read_text(encoding="utf-8"))

    if replay:
        return {"_error": "replay_enabled_but_cache_missing", "_params": params}

    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(NVD_SEARCH_URL, headers=headers, params=params, timeout=timeout_s)
    resp.raise_for_status()
    data = resp.json()

    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data