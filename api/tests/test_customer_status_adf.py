"""Tests for customer-status comment → ADF table conversion and round-trip."""

import pytest

from api.app.jira_client import (
    _parse_pipe_table,
    customer_status_comment_to_adf,
)
from api.app.parsing import _adf_node_to_text

SAMPLE_COMMENT = """\
<!-- CVE-Portal-Customer-Status v1 -->

CVE Status Report - May 27, 2026

Note: The "Expected Release Date" is an estimate and may be subject to change.

Status definitions:
- In progress: CVE is under evaluation or no vendor fix is available yet
- N/A: Package not present in this image

CVE          | Image                | Package | Expected release date | Fix Version
-------------+----------------------+---------+-----------------------+------------
CVE-2025-001 | agent:5.2617.3       | curl    | June 8, 2026          | 5.2624.2
CVE-2026-002 | pip-operator:5.2617.3 | openssl | In progress           | In progress
"""


def test_parse_pipe_table_headers():
    lines = SAMPLE_COMMENT.splitlines()
    result = _parse_pipe_table(lines)
    assert result is not None
    headers, rows = result
    assert headers[0] == "CVE"
    assert headers[1] == "Image"
    assert headers[-1] == "Fix Version"


def test_parse_pipe_table_rows():
    lines = SAMPLE_COMMENT.splitlines()
    result = _parse_pipe_table(lines)
    assert result is not None
    _headers, rows = result
    assert len(rows) == 2
    assert rows[0][0] == "CVE-2025-001"
    assert rows[1][-1] == "In progress"


def test_parse_pipe_table_no_table():
    assert _parse_pipe_table(["no table here", "just plain text"]) is None


def test_customer_status_comment_to_adf_structure():
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    assert doc["type"] == "doc"
    assert doc["version"] == 1
    node_types = [n["type"] for n in doc["content"]]
    assert "table" in node_types


def test_customer_status_comment_to_adf_table_rows():
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    table = next(n for n in doc["content"] if n["type"] == "table")
    rows = table["content"]
    assert rows[0]["content"][0]["type"] == "tableHeader"
    assert rows[1]["content"][0]["type"] == "tableCell"
    # header + 2 data rows
    assert len(rows) == 3


def test_customer_status_comment_to_adf_column_count():
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    table = next(n for n in doc["content"] if n["type"] == "table")
    header_row = table["content"][0]
    assert len(header_row["content"]) == 5  # CVE | Image | Package | Expected... | Fix Version


def test_adf_round_trip_contains_marker():
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    text = _adf_node_to_text(doc)
    assert "CVE-Portal-Customer-Status v1" in text


def test_adf_round_trip_table_cells():
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    text = _adf_node_to_text(doc)
    assert "CVE-2025-001" in text
    assert "In progress" in text


def test_adf_node_to_text_table_nodes():
    """_adf_node_to_text handles table/tableRow/tableHeader/tableCell."""
    doc = customer_status_comment_to_adf(SAMPLE_COMMENT)
    text = _adf_node_to_text(doc)
    # Table rows should be present as pipe-separated lines
    assert " | " in text


def test_no_table_fallback():
    plain = "<!-- CVE-Portal-Customer-Status v1 -->\nNo table here."
    doc = customer_status_comment_to_adf(plain)
    assert doc["type"] == "doc"
    node_types = [n["type"] for n in doc["content"]]
    assert "table" not in node_types
    text = _adf_node_to_text(doc)
    assert "No table here" in text
