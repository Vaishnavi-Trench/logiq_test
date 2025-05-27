from pydantic import BaseModel, Field
from typing import Literal, Union, Dict, Any, TypedDict, List, Optional


############## sense related classes
class AlertNameResponse(BaseModel):
    alert_name: str  # Define the expected structured output as a string


class EnrichedAlert(BaseModel):
    desc: str = Field(description="<description>")
    type: str = Field(description="<type>")


class Findings(BaseModel):
    finding: str = Field(description="<finding>")
    type: str = Field(
        description='Classify each finding as either "good" (indicating no risk or normal behavior) or "bad" (indicating suspicious or malicious activity).'
    )


class FindingAnalysis(BaseModel):
    findings: List[Findings] = Field(description="List of findings")


class Impacted_AssetsAnalysis(BaseModel):
    users: List[str] = Field(description="List of impacted users")
    ips: List[str] = Field(description="List of impacted IP addresses")
    domains: List[str] = Field(description="List of impacted domains")
    hosts: List[str] = Field(description="List of impacted hosts")
    emails: List[str] = Field(description="List of impacted email addresses")


class TriageAnswer(BaseModel):
    answer: str
    reason: str


class TTP(BaseModel):
    tac_id: str = Field(description="<Tactic_id>")
    teq_id: List[str] = Field(description="<technique_id>")


class TTPAnalysis(BaseModel):
    ttps: List[TTP] = Field(description="List of ttp id")


class VerdictStep(BaseModel):
    step_id: str = Field(description="<id>")
    desc: str = Field(
        description="short 1 liner justification for how the answer PASS/FAIL influenced the verdict. Highlight data."
    )


class Verdict(BaseModel):
    steps: List[VerdictStep] = Field(description="List of steps")
    verdict: str = Field(description="<Malicious/Suspicious/False Alert/Inconclusive>")


class VerdictExplanation(BaseModel):
    verdict_explanation: str = Field(
        description="Final conclusive explanation which justifies the given score. Enclose important keywords/data points within **Word** so that I can use it to highlight on UI."
    )


########### genix related classes
class TriageQuestion(BaseModel):
    triage_question: str
    pass_condition: str
    severity: str


class TriageQuestions(BaseModel):
    questions: List[TriageQuestion]
    ttp: str


class ValidatedTriageQuestion(BaseModel):
    isValid: bool
    revised_triage_question: str
    pass_condition: str
    severity: str
    validation_feedback: str


class EnrichedStep(BaseModel):
    use_case: str
    agent_cot: List[str]


class StepValidationFeedback(BaseModel):
    isValid: bool
    question_id: str
    validation_issues: str
    validation_feedback: str


class PlanStepInputParams(BaseModel):
    input_param_name: str
    type: str  # metadata or tool_call
    step_id: Optional[int] = (
        None  # Optional, only if type is tool_call. Add default None.
    )
    field_name: str  # Field name to be extracted from the metadata or output of the tool_call step


class PlanExecutionStep(BaseModel):
    step_sequence_id: int
    task: str
    tool_name: str
    input_params: List[PlanStepInputParams]


class ExecutionPlan(BaseModel):
    total_steps: int
    steps: List[PlanExecutionStep]


class BuildPlanValidatinFeedback(BaseModel):
    isValid: bool
    question_id: str
    validation_issues: Optional[str] = None
    validation_feedback: Optional[str] = None
