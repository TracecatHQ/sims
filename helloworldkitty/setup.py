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

from helloworldkitty.config import (
    HWK__HOME_DIR,
    HWK__LAB_DIR,
)
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


def _path_to_pkg() -> Path:
    import helloworldkitty

    return resources.files(helloworldkitty).parent


def initialize_lab(project_path: Path):
    """Create lab directory and spin-up Terraform in Docker.

    Parameters
    ----------
    project_path : Path
        Path to Terraform project files.
    """

    if os.path.exists(HWK__LAB_DIR):
        raise ValueError(
            "Unable to create new lab as lab already exists. Try running `hwk cleanup`."
        )

    # Create Terraform on Docker
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Create Terraform in Docker container")
    subprocess.run(
        ["docker", "compose", "-f", _path_to_pkg() / "docker-compose.yaml", "up", "-d"]
    )

    # Copy Terraform project into labs
    logger.info("🐱 Create new lab directory")
    os.makedirs(HWK__LAB_DIR, exist_ok=True)

    logger.info("🚧 Copy Terraform project into lab")
    shutil.copytree(project_path, HWK__LAB_DIR)

    logger.info("🚧 Initialize Terraform project")
    subprocess.run(
        ["docker", "compose", "run", "--rm", "terraform", "init"],
        cwd=_path_to_pkg(),
    )


def deploy_lab() -> Path:
    """Deploy lab infrastructure ready for attacks.

    Assumes lab project files already configured and Terraform in Docker is available.
    """
    # Terraform plan (safety)
    # TODO: Capture stdout and deal with errors
    logger.info("🚧 Create Terraform in Docker container")
    tf_plan_cmd = ["docker", "compose", "run", "--rm", "terraform", "plan"]
    subprocess.run(
        tf_plan_cmd,
        cwd=_path_to_pkg(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Terraform deploy
    # TODO: Capture stdout and deal with errors


class FailedTerraformDestroy(Exception):
    pass


def cleanup_lab():
    """Destroy live infrastructure and stop Terraform Docker container.

    Raises
    ------
    FailedTerraformDestory if `terraform destroy` was unsuccessful.
    Container is not stopped in this case.
    """

    def _check_successful_destroy(stdout) -> bool:
        stdout_lines = stdout.strip()
        return "Destroy complete!" in stdout_lines

    # Terraform destroy
    logger.info("🧹 Destroy lab infrastructure")
    tf_destroy_cmd = ["docker", "compose", "run", "--rm", "terraform", "destroy"]
    tf_destroy_output = subprocess.run(
        tf_destroy_cmd,
        cwd=_path_to_pkg(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Check if successfully destroyed
    if not _check_successful_destroy(tf_destroy_output.stdout):
        raise FailedTerraformDestroy(tf_destroy_output.stderr)

    # Delete docker project
    logger.info("🧹 Spin down Terraform in Docker")
    subprocess.run(["docker", "compose", "down"], cwd=_path_to_pkg())

    # Delete labs directory
    logger.info("🧹 Delete lab directory")
    try:
        shutil.rmtree(HWK__LAB_DIR)
    except FileNotFoundError:
        logger.info("❗ No lab directory found")
    logger.info("✅ Lab cleanup successful! What will you break next?")


if __name__ == "__main__":
    project_path = _path_to_pkg() / "helloworldkitty/attack/scenarios/codebuild"
    # initialize_lab(project_path=project_path)
    cleanup_lab()
