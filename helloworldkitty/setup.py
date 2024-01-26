from ipaddress import ip_address
from pathlib import Path

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from helloworldkitty.config import HWK__HOME_DIR
from helloworldkitty.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


def create_ip_whitelist(dir_path: Path | None = None):
    """Write own IP address into whitelist.

    The whitelist is stored in ~/.helloworldkitty.
    """
    logger.info("Add own IP to whitelist")
    dir_path = dir_path or HWK__HOME_DIR
    rsp = requests.get("https://ifconfig.co/json")
    rsp.raise_for_status()
    own_ip_address = ip_address(rsp.json().get("ip"))
    with open(dir_path / "whitelist.txt", "w") as f:
        f.write(str(own_ip_address))


def create_compromised_ssh_keys(dir_path: Path | None = None):
    """Write own IP address into whitelist.

    WARNING: These keys grant access to compromised EC2 instances
    that are deployed for the labs. The compromised SSH keys are
    stored in ~/.helloworldkitty.
    """
    dir_path = dir_path or HWK__HOME_DIR

    logger.info("Generate compromised SSH keys")
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

    # Get and serialize public key in PEM format
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write the public key to a file
    pub_file_path = dir_path / "cloudgoat.pub"
    with open(pub_file_path, "wb") as f:
        f.write(public_pem)


if __name__ == "__main__":
    create_ip_whitelist()
    create_compromised_ssh_keys()
