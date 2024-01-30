from ipaddress import ip_address
from pathlib import Path
import io

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from tracecat.config import TRACECAT__LAB_DIR
from tracecat.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


def create_ip_whitelist(dir_path: Path | None = None):
    """Write own IP address into whitelist.

    The whitelist is stored in ~/.tracecat.
    """
    logger.info("🚧 Add own IP to whitelist")
    dir_path = dir_path or TRACECAT__LAB_DIR
    rsp = requests.get("https://ifconfig.co/json")
    rsp.raise_for_status()
    own_ip_address = ip_address(rsp.json().get("ip"))
    with open(dir_path / "whitelist.txt", "w") as f:
        # Single host
        f.write(str(own_ip_address) + "/32")


def create_compromised_ssh_keys(dir_path: Path | None = None):
    """Write own IP address into whitelist.

    WARNING: These keys grant access to compromised EC2 instances
    that are deployed for the labs. The compromised SSH keys are
    stored in ~/.tracecat.
    """
    dir_path = dir_path or TRACECAT__LAB_DIR

    logger.info("🚧 Create temporary compromised SSH keys for lab")
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

    # Serialize private key in PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        # This format is more akin to what ssh-keygen generates
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),  # No passphrase
    )

    # Write the private key to a file
    priv_file_path = dir_path / "cloudgoat"
    with open(priv_file_path, "wb") as f:
        f.write(private_pem)

    # Get and serialize public key in OpenSSH format
    public_key = private_key.public_key()
    public_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )

    # Write the public key to a file in OpenSSH format
    pub_file_path = dir_path / "cloudgoat.pub"
    with open(pub_file_path, "wb") as f:
        f.write(public_ssh)
