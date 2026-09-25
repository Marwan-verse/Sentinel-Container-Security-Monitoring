import os
from pathlib import Path

DB_PATH = Path(os.getenv("SENTINEL_DB", "data/sentinel.db"))
MODE = os.getenv("SENTINEL_MODE", "auto").lower()
POLL_SECONDS = max(5, int(os.getenv("SENTINEL_POLL_SECONDS", "10")))

