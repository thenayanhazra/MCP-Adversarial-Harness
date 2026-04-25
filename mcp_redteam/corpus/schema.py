"""Pydantic models for the attack payload corpus."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class InjectionPoint(str, Enum):
    description = "description"  # spliced into a tool's description field
    result = "result"            # returned as a tool call result
    param = "param"              # embedded in a user turn / parameter value


class Category(str, Enum):
    EXFIL = "EXFIL"
    HIJACK = "HIJACK"
    CTX_OVERRIDE = "CTX_OVERRIDE"
    DECEPTION = "DECEPTION"
    SHADOW = "SHADOW"
    PARAM_SMUGGLE = "PARAM_SMUGGLE"
    RESULT_POISON = "RESULT_POISON"
    CONFUSED_DEPUTY = "CONFUSED_DEPUTY"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


# ---------------------------------------------------------------------------
# Success criteria
# ---------------------------------------------------------------------------

class ToolCalledCriteria(BaseModel):
    type: Literal["tool_called"]
    tool_name: str | None = None  # None = any tool
    with_arg_containing: str | None = None  # if set, arg value must contain this


class ToolNotCalledCriteria(BaseModel):
    type: Literal["tool_not_called"]
    tool_name: str


class OutputContainsCriteria(BaseModel):
    type: Literal["output_contains"]
    pattern: str  # regex applied to final assistant turn


class OutputNotContainsCriteria(BaseModel):
    type: Literal["output_not_contains"]
    pattern: str


class AnyToolCalledCriteria(BaseModel):
    type: Literal["any_tool_called"]
    except_tools: list[str] = Field(default_factory=list)


class LLMJudgeCriteria(BaseModel):
    type: Literal["llm_judge"]
    question: str   # yes/no question put to the LLM judge
    positive_label: str = "yes"


SuccessCriteria = (
    ToolCalledCriteria
    | ToolNotCalledCriteria
    | OutputContainsCriteria
    | OutputNotContainsCriteria
    | AnyToolCalledCriteria
    | LLMJudgeCriteria
)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

class Payload(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]+-\d{3}$")
    category: Category
    name: str
    injection_point: InjectionPoint
    payload_text: str
    # User turn sent to the agent before/instead of the injected payload.
    # If None a generic benign request is generated from the server's tools.
    user_prompt: str | None = None
    # Tool whose description or result carries the payload (None = first tool).
    target_tool: str | None = None
    success_criteria: SuccessCriteria = Field(discriminator="type")
    cwe_refs: list[str] = Field(default_factory=list)
    severity: Severity = Severity.high
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("cwe_refs", mode="before")
    @classmethod
    def normalise_cwe(cls, v: Any) -> list[str]:
        if isinstance(v, list):
            return [str(x) for x in v]
        return v


class CorpusFile(BaseModel):
    """Top-level wrapper so a YAML file can be either a list or a mapping."""
    payloads: list[Payload]
