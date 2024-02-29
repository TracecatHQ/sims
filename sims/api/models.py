from pydantic import BaseModel


class WebsocketData(BaseModel):
    uuid: str
    technique_ids: list[str]
    scenario_id: str
    timeout: int | None = None
    max_tasks: int | None = None
    max_actions: int | None = None
