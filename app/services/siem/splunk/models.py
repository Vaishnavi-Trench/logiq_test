from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Annotated, TypedDict
import operator


class IndexName(BaseModel):
    index_name: str = Field(
        description="The name of the Splunk index to query."
    )
    
class SplunkQueryTemplate(BaseModel):
    query_template: str = Field(
        description="The Splunk query to execute."
    )
    
class SplunkQuery(BaseModel):
    query: str = Field(
        description="The final Splunk query after all processing."
    )