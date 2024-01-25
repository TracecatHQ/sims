import os
from pathlib import Path

TRACECAT__HOME_DIR = (
    Path(os.environ.get("TRACECAT__HOME_DIR", "~/.tracecat")).expanduser().resolve()
)

TRACECAT__HWK_DIR = TRACECAT__HOME_DIR / "hwk"
