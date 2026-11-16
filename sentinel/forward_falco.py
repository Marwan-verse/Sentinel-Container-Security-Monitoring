"""Forward Falco JSON lines from stdin to the authenticated Sentinel endpoint.

Example: falco -o json_output=true | python -m sentinel.forward_falco
"""
import json
import os
import sys
import time

import requests


def main():
    token = os.getenv("SENTINEL_FALCO_TOKEN")
    if not token:
        raise SystemExit("Set SENTINEL_FALCO_TOKEN before forwarding events")
    url = os.getenv("SENTINEL_FALCO_URL", "http://127.0.0.1:8000/api/runtime/falco")
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
    for line in sys.stdin:
        try:
            payload = json.loads(line)
        except ValueError:
            continue  # Falco can also write startup messages to stdout.
        if not isinstance(payload, dict) or "rule" not in payload:
            continue
        if payload.get("output_fields", {}).get("container.id") in (None, "", "host"):
            continue
        for attempt in range(6):
            try:
                response = session.post(url, json=payload, timeout=10)
                if response.ok:
                    break
                if response.status_code in (401, 403):
                    raise SystemExit("Falco forwarding rejected: check the bearer token")
                code = response.status_code
            except requests.RequestException:
                code = "connection error"
            if attempt == 5:
                # Never print the original payload: it can contain credentials.
                print(f"Falco delivery failed after 6 attempts ({code})", file=sys.stderr)
            else:
                time.sleep(min(2 ** attempt, 10))


if __name__ == "__main__":
    main()
