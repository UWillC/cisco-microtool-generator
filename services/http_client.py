import json
import urllib.request
from typing import Any


def http_get_json(url: str, timeout_seconds: int = 10) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "cisco-microtool-generator/0.3.3 (+https://github.com/UWillC/cisco-microtool-generator)"
        },
        method="GET",
    )

    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)
