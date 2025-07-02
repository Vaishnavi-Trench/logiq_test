from enum import Enum
from typing import List

from pydantic import BaseModel, Field


class QuestionType(str, Enum):
    SINGLE_SELECT = "singleselect"
    MULTI_SELECT = "multiselect"
    TEXT = "text"
    TABLE_SELECT = "tableselect"


class FeedbackQuestion(BaseModel):
    question_id: int
    question: str
    feedback_type: QuestionType
    options: List[str] = Field(
        default_factory=list,
        description="Options for single or multi-select questions, empty otherwise",
    )


class FeedbackForm(BaseModel):
    """Represents the structured alert context extracted by the LLM."""

    questions: List[FeedbackQuestion] = Field(default_factory=list)


class Feedback(BaseModel):
    """Represents the structured alert context extracted by the LLM."""

    table_name: str = Field(
        description="Name of the table to which the feedback applies"
    )
    updated_description: str = Field(
        description="Updated description for the table based on feedback"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="List of tags to be applied to the table",
    )
    reasoning: str = Field(description="Reasoning for the changes made to the table")


class FeedbackOutput(BaseModel):
    """Represents the structured alert context extracted by the LLM."""

    feedback: List[Feedback] = Field(
        default_factory=list,
        description="List of feedback for both the tables old and new",
    )
