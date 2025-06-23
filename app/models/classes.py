from enum import Enum
from typing import Literal, Union, Dict, Any, TypedDict, List, Optional

from pydantic import BaseModel, Field


############## sense related classes
class FacetTagsResponse(BaseModel):
    tags: List[str] = Field(
        description="List of tags that are relevant to the facet template"
    )


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


class Remediations(BaseModel):
    """
    Remediation model to store remediation details.
    """

    actions: list[dict[str, Any]] = Field(
        description="List of remediation actions to be taken. Each action should include 'action' and 'priority'."
    )


class AlertOverview(BaseModel):
    overview: str = Field(
        description="A brief overview of the alert, including key details and context."
    )


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


class PriorityChangedQuestion(BaseModel):
    question: str = Field(description="The question text")
    original_priority: str = Field(description="Original priority")
    new_priority: str = Field(description="New (lower) priority")
    justification: str = Field(
        description="Reason for lowering the priority in this context"
    )


class Verdict(BaseModel):
    verdict: str = Field(description="<Malicious/Suspicious/False Alert/Inconclusive>")
    summary: str = Field(
        description="Summary of the all the steps taken to reach the verdict"
    )
    priority_changed_questions: List[PriorityChangedQuestion] = Field(
        default_factory=list,
        description="List of questions whose priority was changed from higher to lower due to None answers, with justification. Structure: [{ 'question': str, 'original_priority': str, 'new_priority': str, 'justification': str }, ...]",
    )


class VerdictExplanation(BaseModel):
    verdict_explanation: str = Field(
        description="Final conclusive explanation which justifies the given score. Enclose important keywords/data points within **Word** so that I can use it to highlight on UI."
    )


########### genix related classes
class LogSource(str, Enum):
    AZURE_FIREWALL = "azure_firewall"
    AZURE_AD = "azure_ad"
    AZURE_MONITOR = "azure_monitor"
    AZURE_APP_INSIGHTS = "azure_app_insights"
    AZURE_STORAGE = "azure_storage"
    WINDOWS_EVENT_LOG = "windows_event_log"
    LINUX_SYSLOG = "linux_syslog"
    JUMPCLOUD = "jumpcloud"
    CROWDSTRIKE = "crowdstrike"
    CLOUDFLARE = "cloudflare"
    GOOGLE_WORKSPACE = "google_workspace"
    NIGHTFALL_DLP = "nightfall_dlp"
    SALESFORCE = "salesforce"
    DATADOG = "datadog"
    CLOUDANIX = "cloudanix"
    MICROSOFT_DEFENDER_FOR_CLOUD = "microsoft_defender_for_cloud"
    MICROSOFT_SENTINEL = "microsoft_sentinel"


class DeviceType(str, Enum):
    ENDPOINT = "endpoint"
    SERVER = "server"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    VPN_GATEWAY = "vpn_gateway"
    IAM_SYSTEM = "iam_system"
    CLOUD_RESOURCE = "cloud_resource"
    IDENTITY_PROVIDER = "identity_provider"
    APPLICATION = "application"
    WEB_SERVICE = "web_service"
    MOBILE_DEVICE = "mobile_device"


class SecurityEventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PROCESS_ACTIVITY = "process_activity"
    FILE_ACTIVITY = "file_activity"
    NETWORK_ACTIVITY = "network_activity"
    MALWARE_ACTIVITY = "malware_activity"
    CONFIGURATION_CHANGE = "configuration_change"
    ACCOUNT_MANAGEMENT = "account_management"
    DATA_ACCESS = "data_access"
    CLOUD_ACTIVITY = "cloud_activity"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    SYSTEM_HEALTH = "system_health"
    COMPLIANCE = "compliance"
    THREAT_INTELLIGENCE = "threat_intelligence"
    DATA_LOSS_PREVENTION = "data_loss_prevention"
    API_USAGE = "api_usage"


class TriageQuestion(BaseModel):
    triage_question: str
    tags: List[str]


class TriageTag(BaseModel):
    log_source: LogSource
    device_type: Optional[List[DeviceType]]
    security_event_category: Optional[List[SecurityEventCategory]]


class TriageScope(BaseModel):
    tag: TriageTag


class TriageQuestions(BaseModel):
    questions: List[TriageQuestion]
    ttp: str


class ValidatedTriageQuestion(BaseModel):
    isValid: bool
    revised_triage_question: str
    instruction_for_regeneration: str
    pass_condition: str
    importance: str
    validation_feedback: str


class AnalyzedQuestion(BaseModel):
    question: str = Field(description="The triage question text")
    importance: str = Field(description="Importance level: Critical/High/Medium/Low")
    pass_condition: str = Field(
        description="True if 'Yes' means normal behavior, False if 'Yes' means suspicious"
    )
    keep: bool = Field(
        description="Whether to keep this question (true) or discard as redundant (false)"
    )
    reasoning: str = Field(
        description="Explanation for importance, pass condition, and redundancy decisions"
    )


class AssignImportanceAndConditions(BaseModel):
    analyzed_questions: List[AnalyzedQuestion] = Field(
        description="List of analyzed questions with importance, conditions, and redundancy assessment"
    )


class EnrichedStep(BaseModel):
    use_case: str
    triage_conclusion_guidance: str
    agent_cot: List[str]


class StepValidationFeedback(BaseModel):
    isValid: bool
    instruction_to_regeneration: str
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


########### Logiq related classes
class Environment(BaseModel):
    env: str


class TableName(BaseModel):
    table_name: str


class QueryTemplate(BaseModel):
    query_template: str


class TimeRangeReplacement(BaseModel):
    replaced_query: str


class FinalQuery(BaseModel):
    final_query: str


class QueryTemplateOutput(BaseModel):
    """Output model for the query template."""

    query_template: str


class ExtractedField(BaseModel):
    """Represents a single extracted field from the alert context."""

    id: str
    description: str
    field_name: str
    value: str
    confidence: str


class AlertClassification(BaseModel):
    """Represents the classification of the alert."""

    category: str
    sub_category: List[str] = Field(default_factory=list)


class AlertContext(BaseModel):
    """Represents the structured alert context extracted by the LLM."""

    alert_classification: AlertClassification
    extracted_fields: List[ExtractedField] = Field(default_factory=list)


class AlertContextResponse(BaseModel):
    """Wrapper model for the alert context."""

    alert_context: AlertContext


########radar classes
class SuggestedRule(BaseModel):
    """Represents a suggested rule based on alert context."""

    name: str
    description: str
    intention: str
    reason: str
    fields_needed: List[str]
    query_instructions: str
    importance: Literal["Critical", "High", "Medium", "Low"]


class SuggestedRules(BaseModel):
    """Model for suggesting rules based on alert context."""

    rules: List[SuggestedRule] = Field(default_factory=list)


class DataSource(BaseModel):
    name: str
    reason: str
    confidence: Literal["High", "Medium", "Low"]


class DataSources(BaseModel):
    """Model for suggesting rules based on alert context."""

    sources: List[DataSource] = Field(default_factory=list)


# Nurix related classes
class Feedbacks(BaseModel):
    point: str = Field(
        description='<feedback> feedback references an entity (such as a user, IP, or organization) that is specified in the triage record, replace general references (e.g., "The user") with the specific entity from the triage data.'
    )
    priority: str = Field(
        description='Classify each point as either "low", "medium" and "high".'
    )


class FeedbackAnalysis(BaseModel):
    feedbacks: List[Feedbacks] = Field(description="List of points")


class DatapointEntity(BaseModel):
    type: str = Field(
        description="Classify the entity type as either ipaddress, user, domain, file, process, url, hash, or other."
    )
    value: str = Field(
        description="The specific value of the entity, such as an IP address, user name, domain name, file name, process name, URL, or hash."
    )


class InstructionInsight(BaseModel):
    type: str = Field(
        description='Classify the content type as either "playbook" or "datapoint".'
    )
    content: str = Field(
        description="A concise and actionable data point extracted from the feedback and triage label."
    )

    confidence: str = Field(
        description="Classify the insight as either 'low', 'medium', or 'high' based on its significance for future triaging."
    )
    reason: str = Field(
        description="A brief explanation of why this insight was derived from the given input."
    )
    entities: Optional[List[DatapointEntity]] = Field(
        description="Applicable for type: datapoint only. List of entities related to the insight, such as IP addresses, users, domains, etc."
    )


class InstructionInsightsAnalysis(BaseModel):
    insights: List[InstructionInsight] = Field(
        description="List of extracted insights for future triaging."
    )


class StepInstructionInsight(BaseModel):
    type: str = Field(
        description='Classify the content type as either "playbook" or "datapoint".'
    )
    content: str = Field(
        description="A concise and actionable data point extracted from the feedback and triage label."
    )
    confidence: str = Field(
        description="Classify the insight as either 'low', 'medium', or 'high' based on its significance for future triaging."
    )
    reason: str = Field(
        description="A brief explanation of why this insight was derived from the given input."
    )
    operation: Optional[str] = Field(
        description="Applicable for type: playbook only. The operation to be performed, such as add-question, remove-question, or modify-question."
    )
    entities: Optional[List[DatapointEntity]] = Field(
        description="Applicable for type: datapoint only. List of entities related to the insight, such as IP addresses, users, domains, etc."
    )


class StepInstructionInsightsAnalysis(BaseModel):
    insights: List[StepInstructionInsight] = Field(
        description="List of extracted insights or playbook instructions for future triaging."
    )


class TableNameChangeInstruction(BaseModel):
    type: str = Field(
        description='Classify the content type as either "playbook" or "datapoint".'
    )
    content: str = Field(
        description="A concise and actionable data point extracted from the feedback and triage label."
    )
    confidence: str = Field(
        description="Classify the insight as either 'low', 'medium', or 'high' based on its significance for future triaging."
    )
    reason: str = Field(
        description="A brief explanation of why this insight was derived from the given input."
    )
    correct_table_name: str = Field(
        description="The proper table name extracted from user input, return: 'unknown' if failed to find a table name in the user input.."
    )


class NotesClassification(BaseModel):
    classification: str = Field(
        description='Classify the feedback as either "Informative" or "Playbook Related Instruction".'
    )


class FeedbackImprovementSuggestion(BaseModel):
    category_id: str = Field(description="The category ID of the question.")
    question: str = Field(description="The question of the feedback.")
    answer: str = Field(description="The answer of the feedback.")
    suggestion: str = Field(description="The suggestion for the feedback.")


class FeedbackImprovementSuggestions(BaseModel):
    suggestions: List[FeedbackImprovementSuggestion] = Field(
        description="List of feedback improvement suggestions."
    )


####nteg related classes
# sentinel related classes
class SentinelField(BaseModel):
    column_name: str = Field(
        description="Name of the field in the Sentinel index"
    )
    description: str = Field(
        description="Description of the field in the Sentinel index"
    )
    

class SentinelFieldDescription(BaseModel):
    """
    Model representing a field description in Sentinel.
    """
    descriptions: list[SentinelField] = Field(
        description="Field descriptions mapping field names to their descriptions"
    )


class SentinelSuggestedFields(BaseModel):
    """
    Model representing suggested fields based on field descriptions.
    """

    suggested_fields: list[str] = Field(
        description="List of suggested fields based on the field descriptions"
    )


class SentinelFieldSelectionOutput(BaseModel):
    """Output model for the field selection."""

    suggested_fields: List[str]


class SentinelIndexDescriptionOutput(BaseModel):
    """Output model for the index description."""

    description: str


# splunk related classes
class SplunkIndexDescription(BaseModel):
    """
    Splunk index description model.
    """

    description: str = Field(
        description="Description of the Splunk index",
    )


class SplunkFieldDescription(BaseModel):
    """
    Splunk field description model.
    """

    description: str = Field(
        description="Description of the Splunk field",
    )


# sumologic related classes
class SumoLogicIndexDescriptionOutput(BaseModel):
    """Output model for the index description."""

    description: str


# wazuh related classes
class WazuhFieldsDescription(BaseModel):
    """
    Model representing field descriptions in Wazuh.
    This model contains a mapping of field names to their descriptions.
    """

    fields_description: dict = Field(
        description="Field descriptions mapping field names to their descriptions"
    )


class WazuhIndexDescription(BaseModel):
    """
    Model representing the description of a Wazuh index.
    This model contains a description field that provides details about the index.
    """

    description: str = Field(
        description="Description of the Wazuh index",
    )
