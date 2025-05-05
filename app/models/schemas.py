from pydantic import BaseModel
from typing import Literal, Union, Dict, Any, TypedDict, List, Optional


class QuestionRequest(BaseModel):
    intcid: str
    alert: Dict[str, Any]
    question: str
    cot: list[str]
    pass_cond: str
    fail_cond: str


class QuestionResponseData(BaseModel):
    type: Literal["boolean", "text"]
    answer: Union[bool, str]
    description: str


class QuestionResponse(BaseModel):
    success: bool
    data: QuestionResponseData


class TriageAnswer(TypedDict):
    result: str
    explanation: str


class StatusResponse(BaseModel):
    status: str
    message: str


class ToolParameter(BaseModel):
    name: str
    type: str
    description: str
    default: Optional[str] = None


class Tool(BaseModel):
    name: str
    description: str
    parameters: List[ToolParameter]
    returns: str
