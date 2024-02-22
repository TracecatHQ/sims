import textwrap

import httpx

from tracecat.agents import (
    AWSAPICallAction,
    AWSUser,
    Background,
    Objective,
    Task,
    model_as_text,
)
from tracecat.config import STRATUS__HOME_DIR
from tracecat.llm import async_openai_call


class NoisyStratusUser(AWSUser):
    """The expert false positives generator."""

    def __init__(
        self,
        uuid: str,
        name: str,
        technique_id: str,
        scenario_id: str,
        max_tasks: int | None = None,
        max_actions: int | None = None,
    ):
        self.technique_id = technique_id
        terraform_path = STRATUS__HOME_DIR / technique_id
        super().__init__(
            uuid=uuid,
            name=name,
            scenario_id=scenario_id,
            terraform_path=terraform_path,
            is_compromised=False,
            max_tasks=max_tasks,
            max_actions=max_actions,
        )

    async def _get_background(self) -> str:
        technique_id = self.technique_id
        permissions = self._get_iam()
        url = f"https://raw.githubusercontent.com/DataDog/stratus-red-team/main/docs/attack-techniques/AWS/{technique_id}.md"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            attack_description = response.text
        system_context = textwrap.dedent(
            "You are an expert in reverse engineering Cloud cyber attacks."
            "You are an expert in Cloud activities that produce false positives in a SIEM."
            "You are an expert in spoofing in the Cloud."
        )
        prompt = textwrap.dedent(
            f"""
            Task: Generate a background for a non-malicious AWS user given the attack description:
            ```{attack_description}```

            Also give the AWS user a username that aligns with the following IAM permissions:
            ```{permissions}```

            Intent: Use the same tools and techniques as described in the attack but in a non-malicious way.

            Return a JSON dictionary according to the following pydantic schema:
            {model_as_text(Background)}
            """
        )

        self.logger.info("🧠 Before calling openai for %s...", self.name)
        background = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="json_object",
        )

        self.logger.info("🧠 After calling openai for %s...", self.name)
        return background

    async def _get_objective(self) -> dict:
        permissions = self._get_iam()
        system_context = textwrap.dedent(
            "You are an expert in predicting what users in an organization might do."
            "You are also an expert at breaking down objectives into smaller tasks."
            "You are creative and like to think outside the box."
            "You always mention at least one specific AWS API call in every write-up."
        )
        prompt = textwrap.dedent(
            f"""
            Task: Describe one `Objective` with its constituent `Tasks` and `Actions` according to the following pydantic schema:
            ```
            {model_as_text(Objective)}

            {model_as_text(Task)}

            {model_as_text(AWSAPICallAction)}
            ```
            Return a single structured JSON response.

            Intent: Predict what a user with the following background and IAM permissions might realistically do:
            ```
            Background:
            {self.background}

            IAM permissions:
            {permissions}

            The user has completed the following objectives:
            {self.objectives!s}
            ```
            - Include at least one AWS API call explicitly mentioned in the "Background".
            - Each objective should have no more than {self.max_tasks} tasks.
            - Each task should have no more than {self.max_actions} actions.
            - Give realistic and detailed answers.
            """
        )

        objective = await async_openai_call(
            prompt,
            temperature=1,  # High temperature for creativity and variation
            system_context=system_context,
            response_format="json_object",
        )
        return objective
