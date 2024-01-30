import json
from tracecat.config import TRACECAT__LAB_DIR


def load_lab_credentials(is_compromised: bool = False):
    with open(TRACECAT__LAB_DIR / "terraform/credentials.json") as f:
        key_type = "compromised" if is_compromised else "normal"
        try:
            creds = json.load(f)[key_type]
        except KeyError as err:
            raise KeyError(
                "Expected keys grouped as `compromised` or `normal`."
                f"Found {creds.keys()!r} instead."
            ) from err
    return creds


def get_normal_ids() -> list[str]:
    normal_ids = [
        creds["aws_access_key_id"] for creds in
        load_lab_credentials(is_compromised=False).values()
    ]
    return normal_ids


def get_malicious_ids() -> list[str]:
    malicious_ids = [
        creds["aws_access_key_id"] for creds in
        load_lab_credentials(is_compromised=True).values()
    ]
    return malicious_ids
