"""Customer severity fallback helpers and attachment parsers."""

from __future__ import annotations

import io
import json

import openpyxl

from api.app.parsing import (
    normalize_customer_score,
    normalize_customer_severity,
    parse_attachment_bytes,
    severity_rank,
)


def test_normalize_customer_severity_variants():
    assert normalize_customer_severity("medium") == "MEDIUM"
    assert normalize_customer_severity("3 - Medium") == "MEDIUM"
    assert normalize_customer_severity("CRITICAL") == "CRITICAL"
    assert normalize_customer_severity("moderate") == "MEDIUM"
    assert normalize_customer_severity("") is None
    assert normalize_customer_severity(None) is None


def test_normalize_customer_score():
    assert normalize_customer_score("8.7") == "8.7"
    assert normalize_customer_score("None") is None
    assert normalize_customer_score("") is None


def test_severity_rank_order():
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("MEDIUM")
    assert severity_rank(None) < severity_rank("LOW")


def test_excel_fact_includes_severity():
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(("Vulnerability", "Image Repository", "Tag", "Severity", "CVSS"))
    ws.append(("CVE-2026-59898", "plainid/pip-operator", "1.0", "high", "7.5"))
    buf = io.BytesIO()
    wb.save(buf)
    parsed = parse_attachment_bytes(
        attachment_id="a1",
        filename="scan.xlsx",
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        data=buf.getvalue(),
    )
    assert len(parsed.cve_image_facts) == 1
    assert parsed.cve_image_facts[0].severity == "HIGH"
    assert parsed.cve_image_facts[0].score == "7.5"


def test_aqua_json_fact_includes_severity():
    payload = [
        {
            "image_name": "registry.example.com/plainid/agent:1.0",
            "results": {
                "resources": [
                    {
                        "resource": {"name": "io.netty_netty-codec", "version": "4.1"},
                        "vulnerabilities": [
                            {
                                "name": "CVE-2026-59901",
                                "aqua_severity": "high",
                                "nvd_score_v3": 7.5,
                            }
                        ],
                    }
                ]
            },
        }
    ]
    parsed = parse_attachment_bytes(
        attachment_id="a2",
        filename="aqua.json",
        mime_type="application/json",
        data=json.dumps(payload).encode(),
    )
    assert parsed.cve_image_facts[0].severity == "HIGH"
    assert parsed.cve_image_facts[0].score == "7.5"


def test_aqua_html_fact_includes_severity():
    html = """<!DOCTYPE html><html><head>
<title>reg/plainid/agent:1.0 | Scan Results</title></head><body>
<h1>Scan Report: reg/plainid/agent:1.0</h1>
<table>
<tr><th>Name</th><th>Resource</th><th>Severity</th><th>Score</th><th>Fix Version</th></tr>
<tr><td>CVE-2026-56745</td><td>busybox</td><td>high</td><td>8.7</td><td>None</td></tr>
</table>
</body></html>"""
    parsed = parse_attachment_bytes(
        attachment_id="a3",
        filename="AquaReport.html",
        mime_type="text/html",
        data=html.encode(),
    )
    assert parsed.status == "ok"
    assert parsed.cve_image_facts[0].severity == "HIGH"
    assert parsed.cve_image_facts[0].score == "8.7"
