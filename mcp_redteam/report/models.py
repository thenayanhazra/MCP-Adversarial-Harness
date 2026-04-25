"""Shared Pydantic models for findings and scan results."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from mcp_redteam.corpus.schema import Category, Severity


class Verdict(str, Enum):
    vulnerable = "vulnerable"
    not_vulnerable = "not_vulnerable"
    uncertain = "uncertain"
    error = "error"


class ToolCallRecord(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}
    result: str = ""
    latency_ms: float = 0.0


class TranscriptEntry(BaseModel):
    role: str  # user | assistant | tool
    content: str
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    token_count: int | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    payload_id: str
    category: Category
    severity: Severity
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    judge_type: str = "deterministic"  # deterministic | llm | human
    evidence: str = ""
    tool_calls_observed: list[ToolCallRecord] = Field(default_factory=list)
    transcript: list[TranscriptEntry] = Field(default_factory=list)
    model_id: str = ""
    server_spec: str = ""
    cwe_refs: list[str] = Field(default_factory=list)
    reproducer_command: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_spec: str
    model_id: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    total_probes: int = 0
    total_errors: int = 0

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.vulnerable)

    @property
    def uncertain_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.uncertain)
