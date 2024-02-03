from typing import Literal

from pydantic import BaseModel

Status = Literal["info", "low", "medium", "high", "critical"]
Aggregation = Literal[
    "count",
    "cardinality",
    "sum",
    "max",
    "new_value",
    "geo_data",
    "event_count",
    "none",
]


class Case(BaseModel):
    """Cases for generating signals."""

    condition: str | None = None
    name: str | None = None
    notifications: list[str] | None = None
    status: Status | None = None


class ComplianceSignalOptions(BaseModel):
    defaultActivationStatus: bool | None = None
    defaultGroupByFields: list[str] | None = None
    userActivationStatus: bool | None = None
    userGroupByFields: list[str] | None = None


class Filter(BaseModel):
    action: Literal["require", "suppress"] | None = None
    query: str | None = None


class RegoRule(BaseModel):
    policy: str | None = None
    resourceTypes: list[str] | None = None


class ComplianceRuleOptions(BaseModel):
    complexRule: bool | None = None
    regoRule: RegoRule | None = None
    resourceType: str | None = None
    decreaseCriticalityBasedOnEnv: bool | None = None


class ImpossibleTravelOptions(BaseModel):
    baselineUserLocations: bool | None = None


class NewValueOptions(BaseModel):
    forgetAfter: Literal[1, 2, 7, 14, 21, 28] | None = None
    learningDuration: Literal[0, 1, 7] | None = None
    learningMethod: Literal["duration", "threshold"] | None = "duration"
    learningThreshold: Literal[0, 1] | None = None


class RootQuery(BaseModel):
    groupByFields: list[str] | None = None
    query: str | None = None


class ThirdPartyRuleOptions(BaseModel):
    defaultNotifications: list[str] | None = None
    defaultStatus: Status | None = None
    rootQueries: list[RootQuery] | None = None
    signalTitleTemplate: str | None = None


class QueryMatchingRule(BaseModel):
    """Query for matching rule."""

    aggregation: Aggregation | None = None
    distinctFields: list[str] | None = None
    groupByFields: list[str] | None = None
    metric: str | None = None
    metrics: list[str] | None = None
    name: str | None = None
    query: str | None = None


class QueryMatchingRuleOnSignals(BaseModel):
    """Query for matching rule on signals."""

    aggregation: Aggregation | None = None
    correlatedByFields: list[str] | None = None
    correlatedQueryIndex: int | None = None
    metrics: list[str] | None = None
    name: str | None = None
    ruleId: str | None = None


Query = QueryMatchingRule | QueryMatchingRuleOnSignals


class ThirdPartyCase(BaseModel):
    name: str | None = None
    notifications: list[str] | None = None
    query: str | None = None
    status: Status | None = None


class Options(BaseModel):
    complianceRuleOptions: ComplianceRuleOptions | None = None
    decreaseCriticalityBasedOnEnv: bool | None = None
    detectionMethod: (
        Literal[
            "threshold",
            "new_value",
            "anomaly_detection",
            "impossible_travel",
            "hardcoded",
            "third_party",
        ]
        | None
    ) = None
    evaluationWindow: Literal[0, 60, 300, 600, 900, 1800, 3600, 7200] | None = None
    hardcodedEvaluatorType: Literal["log4shell"] | None = None
    impossibleTravelOptions: ImpossibleTravelOptions | None = None
    keepAlive: (
        Literal[0, 60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600] | None
    ) = None
    maxSignalDuration: (
        Literal[0, 60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]
        | None
    ) = None
    newValueOptions: NewValueOptions | None = None
    thirdPartyRuleOptions: ThirdPartyRuleOptions | None = None


class RuleUpdateRequest(BaseModel):
    cases: list[Case] | None = None
    complianceSignalOptions: ComplianceSignalOptions | None = None
    filters: list[Filter] | None = None
    hasExtendedTitle: bool | None = None
    isEnabled: bool | None = None
    message: str | None = None
    name: str | None = None
    options: Options | None = None
    queries: list[Query] | None = None
    tags: list[str] | None = None
    thirdPartyCases: list[ThirdPartyCase] | None = None
    version: int | None = None
