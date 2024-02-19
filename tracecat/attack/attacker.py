import subprocess
import textwrap

from tracecat.agents import AWSAPICallAction, AWSUser, Objective, Task, model_as_text
from tracecat.config import STRATUS__HOME_DIR
from tracecat.llm import async_openai_call


class MaliciousStratusUser(AWSUser):
    """The hacker."""

    def __init__(
        self,
        uuid: str,
        name: str,
        technique_id: str,
        max_tasks: int | None = None,
        max_actions: int | None = None,
    ):
        self.technique_id = technique_id
        terraform_path = STRATUS__HOME_DIR / technique_id
        super().__init__(
            uuid=uuid,
            name=name,
            terraform_path=terraform_path,
            is_compromised=True,
            max_tasks=max_tasks,
            max_actions=max_actions,
        )

    async def _get_background(self) -> str:
        technique_id = self.technique_id
        stratus_show_output = subprocess.run(
            ["stratus", "show", technique_id], capture_output=True, text=True
        )
        attack_description = stratus_show_output.stdout
        system_context = (
            "You are an expert Cloud cybersecurity professional."
            "You are an expert red teamer."
            "You always mention at least one specific AWS API call in every write-up."
        )
        prompt = (
            f"Your task is to create an attacker motive that aligns with this attack description:\n```{attack_description}```"
            "\nThe motive can be financial (extortion, ransomops, crytohacking, etc.), state-sponsored, or hacktist."
            "Refer to specific advanced persistent threat (APT) actors align with the tactics, techniques, and procecures (TTPs) in the attack description."
        )
        background = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="text",
            model="gpt-3.5-turbo-1106",
        )
        return background

    async def _get_objective(self) -> dict:
        system_context = (
            "You are an expert in predicting what a motivated cyber threat actor might do."
            "You are also an expert at breaking down objectives into smaller tasks."
            "You are creative and like to think outside the box."
        )
        prompt = textwrap.dedent(
            f"""
            Please describe one `Objective` with its constituent `Tasks` and `Actions` according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {model_as_text(AWSAPICallAction)}
            ```
            You are to generate a single structured JSON response.

            Your goal in describing the `Objective` is to predict what a malicious user with the following background might realistically do:
            ```
            Background:
            {self.background}

            The user has completed the following objectives:
            {self.objectives!s}
            ```

            You must select one AWS API call explicitly mentioned in the "Background".
            Each objective should have no more than {self.max_tasks} tasks.
            Each task should have no more than {self.max_actions} actions.
            Please be realistic and detailed.
            """
        )

        objective = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="json_object",
        )
        return objective
