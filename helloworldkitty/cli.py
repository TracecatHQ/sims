import typer
from typing_extensions import Annotated

from helloworldkitty.attack.ddos import ddos as signal_ddos
from helloworldkitty.setup import cleanup_lab, deploy_lab, initialize_lab

app = typer.Typer()


@app.command()
def warmup(
    project_path: Annotated[str, typer.Argument(help="Path to Terraform project")],
):
    """Create lab ready for attacks."""
    initialize_lab(project_path=project_path)
    deploy_lab(project_path=project_path)


@app.command()
def detonate():
    pass


@app.command()
def ddos(n_attacks: int = 10, delay: int = 1):
    signal_ddos(n_attacks=n_attacks, delay=delay)


@app.command()
def cleanup():
    delete = typer.confirm(
        "Are you sure you want to destroy all resources and scripts in your lab?"
    )
    if not delete:
        print("Cleanup aborted.")
        raise typer.Abort()
    print("🧹 Run lab cleanup")
    cleanup_lab()


if __name__ == "__main__":
    app()
