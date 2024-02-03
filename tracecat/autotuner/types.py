from typing import Any, Literal

from pydantic import BaseModel

from tracecat.schemas.datadog import RuleUpdateRequest


# For compliance with frontend
class DatadogRule(BaseModel):
    id: str
    source: str
    ruleName: str
    severity: str
    ttp: str
    score: int
    timeSavable: int
    status: str
    queries: list[Any]
    cases: list[Any]


class ElasticRule(BaseModel):
    id: str
    queries: list[dict[str, Any]]
    cases: list[dict[str, Any]]


Rule = RuleUpdateRequest
RuleType = Literal["datadog", "elastic"]
