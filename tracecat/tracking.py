"""Context manager to track identities used in attacks.
"""

from contextlib import contextmanager
from pathlib import Path

import boto3
import orjson


@contextmanager
def track_aws_credential_keys(path: Path, is_malicious: bool = False):
    original_boto3_session = boto3.Session
    original_boto3_client = boto3.client
    accessed_keys = set()

    def custom_boto3_session(*args, **kwargs):
        if "aws_access_key_id" in kwargs:
            accessed_keys.add(kwargs["aws_access_key_id"])
        return original_boto3_session(*args, **kwargs)

    def custom_boto3_client(*args, **kwargs):
        if "aws_access_key_id" in kwargs:
            accessed_keys.add(kwargs["aws_access_key_id"])
        return original_boto3_client(*args, **kwargs)

    boto3.Session = custom_boto3_session
    boto3.client = custom_boto3_client

    yield

    boto3.Session = original_boto3_session
    boto3.client = original_boto3_client

    with open(path, "w") as file:
        for key in accessed_keys:
            json_line = orjson.dumps(
                {"aws_access_key_id": key, "is_malicious": is_malicious}
            )
            file.write(json_line + "\n")
