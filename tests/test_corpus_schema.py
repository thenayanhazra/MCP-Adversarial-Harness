"""Tests for corpus schema validation and built-in payload loading."""

from __future__ import annotations

import pytest

from mcp_redteam.corpus.loader import load_builtin_corpus
from mcp_redteam.corpus.schema import Category, InjectionPoint, Payload, Severity


def test_load_builtin_corpus_nonempty() -> None:
    payloads = load_builtin_corpus()
    assert len(payloads) >= 80, f"Expected ≥80 payloads, got {len(payloads)}"


def test_all_categories_represented() -> None:
    payloads = load_builtin_corpus()
    found = {p.category for p in payloads}
    for cat in Category:
        assert cat in found, f"Category {cat} has no payloads in built-in corpus"


def test_all_injection_points_represented() -> None:
    payloads = load_builtin_corpus()
    found = {p.injection_point for p in payloads}
    for ip in InjectionPoint:
        assert ip in found, f"InjectionPoint {ip} has no payloads"


def test_payload_ids_unique() -> None:
    payloads = load_builtin_corpus()
    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids)), "Duplicate payload IDs found"


def test_payload_id_format() -> None:
    import re
    pattern = re.compile(r"^[a-z0-9-]+-\d{3}$")
    payloads = load_builtin_corpus()
    for p in payloads:
        assert pattern.match(p.id), f"Bad payload id format: {p.id!r}"


def test_valid_pydantic_payload() -> None:
    p = Payload.model_validate({
        "id": "test-payload-001",
        "category": "EXFIL",
        "name": "Test",
        "injection_point": "description",
        "payload_text": "inject me",
        "success_criteria": {"type": "tool_called", "tool_name": "exfil_data"},
        "severity": "high",
    })
    assert p.category == Category.EXFIL
    assert p.injection_point == InjectionPoint.description
    assert p.severity == Severity.high


def test_invalid_payload_raises() -> None:
    with pytest.raises(Exception):
        Payload.model_validate({
            "id": "BAD ID",  # fails pattern
            "category": "NOT_A_CATEGORY",
            "injection_point": "description",
            "payload_text": "x",
            "success_criteria": {"type": "tool_called", "tool_name": "x"},
        })


def test_success_criteria_discriminator() -> None:
    from mcp_redteam.corpus.schema import (
        LLMJudgeCriteria,
        OutputContainsCriteria,
        ToolCalledCriteria,
    )
    p = Payload.model_validate({
        "id": "test-criteria-001",
        "category": "CTX_OVERRIDE",
        "name": "t",
        "injection_point": "result",
        "payload_text": "x",
        "success_criteria": {"type": "output_contains", "pattern": "foo"},
    })
    assert isinstance(p.success_criteria, OutputContainsCriteria)

    p2 = Payload.model_validate({
        "id": "test-criteria-002",
        "category": "CTX_OVERRIDE",
        "name": "t",
        "injection_point": "result",
        "payload_text": "x",
        "success_criteria": {"type": "llm_judge", "question": "did x happen?"},
    })
    assert isinstance(p2.success_criteria, LLMJudgeCriteria)
