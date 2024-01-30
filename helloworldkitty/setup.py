import os
import shutil
import subprocess
from importlib import resources
from ipaddress import ip_address
from pathlib import Path

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from helloworldkitty.config import TRACECAT__LAB_DIR
from helloworldkitty.logger import standard_logger

logger = standard_logger(__name__, level="INFO")


def create_ip_whitelist(dir_path: Path | None = None):
    """Write own IP address into whitelist.

    The whitelist is stored in ~/.helloworldkitty.
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
    stored in ~/.helloworldkitty.
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


def _path_to_pkg() -> Path:
    import helloworldkitty

    return resources.files(helloworldkitty).parent


def run_terraform(cmds: list[str]):
    subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "-chdir=terraform", *cmds],
        cwd=_path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )


def initialize_lab(project_path: Path):
    """Create lab directory and spin-up Terraform in Docker.

    Parameters
    ----------
    project_path : Path
        Path to Terraform project files.
    """

    logger.info("🐱 Create new lab directory")
    TRACECAT__LAB_DIR.mkdir(parents=True, exist_ok=True)

    # Shared configs
    create_ip_whitelist()
    create_compromised_ssh_keys()

    # Create Terraform on Docker
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Create Terraform in Docker container")
    subprocess.run(
        ["docker", "compose", "-f", _path_to_pkg() / "docker-compose.yaml", "up", "-d"],
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )

    # Copy Terraform project into labs
    logger.info("🚧 Copy Terraform project into lab")
    shutil.copytree(project_path, TRACECAT__LAB_DIR, dirs_exist_ok=True)

    logger.info("🚧 Initialize Terraform project")
    run_terraform(["init"])


def deploy_lab() -> Path:
    """Deploy lab infrastructure ready for attacks.

    Assumes lab project files already configured and Terraform in Docker is available.
    """
    # Terraform plan (safety)
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform plan")
    run_terraform(["plan"])

    # Terraform deploy
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Run Terraform apply")
    run_terraform(["apply"])


class FailedTerraformDestroy(Exception):
    pass


def cleanup_lab():
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """
    # Terraform destroy
    logger.info("🧹 Destroy lab infrastructure")
    run_terraform(["destroy"])

    # Delete labs directory
    logger.info("🧹 Delete lab directory")
    try:
        shutil.rmtree(TRACECAT__LAB_DIR)
    except FileNotFoundError:
        logger.info("❗ No lab directory found")

    # Delete docker containers
    logger.info("🧹 Spin down Terraform in Docker")
    subprocess.run(
        ["docker", "compose", "down"],
        cwd=_path_to_pkg(),
        env={**os.environ.copy(), "UID": str(os.getuid()), "GID": str(os.getgid())},
    )

    logger.info("✅ Lab cleanup complete. What will you break next?")


if __name__ == "__main__":
    project_path = _path_to_pkg() / "helloworldkitty/attack/scenarios/codebuild"
    initialize_lab(project_path=project_path)
    deploy_lab()
    # cleanup_lab()
