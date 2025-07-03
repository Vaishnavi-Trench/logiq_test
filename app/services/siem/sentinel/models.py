from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Annotated, TypedDict
import operator


class Environment(BaseModel):
    env: str
   
class TableName(BaseModel):
    table_name: str
    
# class TableNames(BaseModel):
#     table_names: List[str]
    
class QueryTemplate(BaseModel):
    query_template: str
    
class TimeRangeReplacement(BaseModel):
    replaced_query: str
    
class FinalQuery(BaseModel):
    final_query: str

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
    
class TableSelectionOutput(BaseModel):
    """Output model for the table selection."""
    table_names: List[str]
    
class QueryTemplateOutput(BaseModel):
    """Output model for the query template."""
    query_template: str


class AlertContextEnrichmentQuery(BaseModel):
    """Model for individual KQL query."""
    query: str = Field(description="The KQL query string")
    description: str = Field(description="Description of what this query is searching for")
    index_name: str = Field(description="Target index/table name for the query")
    reason:str = Field(
        description="Reason for generating this query"
    )

class AlertContextEnrichmentQueryList(BaseModel):
    """Model for list of KQL queries."""
    queries: List[AlertContextEnrichmentQuery] = Field(description="List of KQL queries to be executed")