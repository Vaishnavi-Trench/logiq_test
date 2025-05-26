from pydantic import BaseModel, Field
from typing import Literal, Union, Dict, Any, TypedDict, List, Optional


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
