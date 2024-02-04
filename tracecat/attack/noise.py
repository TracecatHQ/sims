import json
import textwrap
import subprocess
from tracecat.config import STRATUS__HOME_DIR
from tracecat.llm import openai_call, async_openai_call
from tracecat.agents import Objective, model_as_text, AWSAPICallAction, Task, AWSAssumeRoleUser


class NoisyStratusUser(AWSAssumeRoleUser):
    """The expert false positives generator."""

    def __init__(
        self,
        name: str,
        technique_id: str,
        max_tasks: int | None = None,
        max_actions: int | None = None,
        mock_actions: bool = False
    ):
        self.technique_id = technique_id
        terraform_path = STRATUS__HOME_DIR / technique_id
        super().__init__(
            name=name,
            terraform_path=terraform_path,
            background=self.get_background(technique_id=technique_id),
            max_tasks=max_tasks,
            max_actions=max_actions,
            mock_actions=mock_actions
        )

    @staticmethod
    def get_background(technique_id: str) -> str:
        stratus_show_output = subprocess.run([
            "docker",
            "run",
            "--rm",
            "ghcr.io/datadog/stratus-red-team",
            "show",
            technique_id
        ], capture_output=True, text=True)
        attack_description = stratus_show_output.stdout
        system_context = (
            "You are an expert in reverse engineering Cloud cyber attacks."
            "You are an expert in Cloud activities that produce false positives in a SIEM."
            "You are an expert in spoofing in the Cloud."
            "You always mention at least one specific AWS API call in every write-up."
        )
        prompt = (
            f"Your task is to rewrite this attack description:\n```{attack_description}```"
            "\nInto a description of a software engineer or DevOps engineer (pick one)."
            "\nUse the same tools and techniques as described in the attack but in a non-malicious way."
        )
        result = openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="text",
        )
        return result

    async def get_objective(self) -> Objective:
        system_context = (
            "You are an expert in predicting what users in an organization might do."
            "You are also an expert at breaking down objectives into smaller tasks."
            "You are creative and like to think outside the box."
        )
        prompt = textwrap.dedent(
            f"""
            Your task is to predict what a user with the following background might realistically do:

            Background:
            {self.background}

            The user has completed the following objectives:
            {self.objectives!s}

            You must select one AWS API call explicitly mentioned in the "Background".

            Please describe an Objective with its constituent Tasks and Actions according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {model_as_text(AWSAPICallAction)}
            ```

            You are to generate a structured JSON response.
            Each objective should have no more than {self.max_tasks} tasks.
            Each task should have no more than {self.max_actions} actions.
            Please be realistic and detailed when describing the objective and tasks.
            """
        )
        # self.logger.info(f"### Get objective prompt\n\n{prom`pt}")
        result = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="json_object",
        )
        self.logger.info(f"New objective:\n```\n{json.dumps(result, indent=2)}\n```")
        obj = Objective(
            name=result["name"],
            description=result["description"],
            tasks=result["tasks"]
        )
        return obj
