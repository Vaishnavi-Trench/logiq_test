

from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Annotated, TypedDict
import operator


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


#RAG
class ExtractedEntity(BaseModel):
    """
    Represents an entity extracted from an alert.
    """
    type: str
    value: str


class AlertContextEntities(BaseModel):
    """
    Represents the context entities extracted from an alert.
    """
    entities: List[ExtractedEntity]




class AlertContext(BaseModel):
    """Represents the structured alert context extracted by the LLM."""

    alert_classification: AlertClassification
    extracted_fields: List[ExtractedField] = Field(default_factory=list)


class AlertContextResponse(BaseModel):
    """Wrapper model for the alert context."""

    alert_context: AlertContext
    
class TableName(BaseModel):
    """Represents the name of a table in the database."""
    
    table_name: str
    
class QueryTemplate(BaseModel):
    """Represents a query template for querying the database."""
    query_template: str
    from_time: str
    to_time: str


class FinalQuery(BaseModel):
    """Represents the final query to be executed against the database."""
    final_query: str