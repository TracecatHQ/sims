import json
from tracecat.config import TRACECAT__LAB_DIR


def load_lab_credentials(is_compromised: bool = False):
    with open(TRACECAT__LAB_DIR / "terraform/credentials.json") as f:
        key_type = "compromised" if is_compromised else "normal"
        try:
            creds = json.load(f)
            selected_creds = creds[key_type]
        except KeyError as err:
            raise KeyError(
                "Expected keys grouped as `compromised` or `normal`."
                f"Found {selected_creds.keys()!r} instead."
            ) from err
    return creds
