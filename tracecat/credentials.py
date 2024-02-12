import json

import boto3

from tracecat.config import TRACECAT__LAB_DIR


def load_lab_credentials(is_compromised: bool = False, load_all: bool = False):
    try:
        with open(TRACECAT__LAB_DIR / "terraform/credentials.json") as f:
            key_type = "compromised" if is_compromised else "normal"
            try:
                creds = json.load(f)
                if not load_all:
                    creds = creds[key_type]
            except KeyError as err:
                raise KeyError(
                    "Expected keys grouped as `compromised` or `normal`."
                    f"Found {creds.keys()!r} instead."
                ) from err
    except FileNotFoundError:
        # If creds not created, assume is a test environment
        creds = {
            "tracecat-user": {
                # Fake keys from https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-methods
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            }
        }
    return creds


def get_normal_ids() -> list[str]:
    normal_ids = [
        creds["aws_access_key_id"]
        for creds in load_lab_credentials(is_compromised=False).values()
    ]
    return normal_ids


def get_malicious_ids() -> list[str]:
    malicious_ids = [
        creds["aws_access_key_id"]
        for creds in load_lab_credentials(is_compromised=True).values()
    ]
    return malicious_ids


def get_caller_identity(
    aws_access_key_id: str,
    aws_secret_access_key: str,
) -> dict:
    sts_client = boto3.client(
        "sts",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    return sts_client.get_caller_identity()


def assume_aws_role(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_role_name: str,
    aws_role_session_name: str,
    aws_account_id: str | None = None,
) -> str:
    """Assumes role given AWS credentials and returns AWS session token."""
    sts_client = boto3.client(
        "sts",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    aws_account_id = aws_account_id or sts_client.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{aws_account_id}:role/{aws_role_name}"
    assumed_role_object = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName=aws_role_session_name
    )
    session_token = assumed_role_object["Credentials"]["SessionToken"]
    return {
        "aws_account_id": aws_account_id,
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
        "aws_session_token": session_token,
    }
