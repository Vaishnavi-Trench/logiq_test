from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional, Annotated, TypedDict
import operator



class IndexAndEnvironment(BaseModel):
    index_name: str = Field(
        description="The name of the Wazuh index to query."
    )
    env: str = Field(
        description="The environment associated with the Wazuh index."
    )

class WazuhAlertContext(BaseModel):
    alert_classification: dict = Field(
        description="The classification of the alert, including details like severity and type."
    )
    extracted_fields: dict = Field(
        description="Fields extracted from the alert, such as agent name, IP address, and event type."
    )

class Environment(BaseModel):
    env: str = Field(
        description="The environment associated with the Wazuh index."
    )
    
class WazuhIndexName(BaseModel):
    index_name: str = Field(
        description="The name of the Wazuh index to query."
    )
    
class WazuhQueryTemplate(BaseModel):
    query_template: str = Field(
        description="The Wazuh query template to execute."
    )
    
class WazuhQuery(BaseModel):
    query: str = Field(
        description="The final Wazuh query after all processing."
    )