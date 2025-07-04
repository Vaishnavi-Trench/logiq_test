from pydantic import BaseModel, Field
from typing import List



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