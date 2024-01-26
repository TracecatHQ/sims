import os
from pathlib import Path

HWK__HOME_DIR = (
    Path(os.environ.get("HWK__HOME_DIR", "~/.helloworldkitty")).expanduser().resolve()
)
