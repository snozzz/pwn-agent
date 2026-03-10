from __future__ import annotations

import json
from pathlib import Path

from .classification import ClassifiedFinding, classify_findings
from .dedup import deduplicate_findings
from .scanner import ScanResult


RULES = {
    "unsafe_copy": ("PA001", "Unsafe copy operation detected"),
    "shell_exec": ("PA002", "Shell execution primitive detected"),
    "raw_memory": ("PA003", "Raw memory operation hotspot detected"),
    "length_math": ("PA004", "Length arithmetic hotspot detected"),
}


def _level(severity: str) -> str:
    return {
        "high": "error",
        "medium": "warning",
        "low": "note",
    }.get(severity, "note")


def sarif_dict(result: ScanResult, verified_signal: bool = False) -> dict:
    findings = deduplicate_findings(classify_findings(result.findings, verified_signal=verified_signal))
    rules = []
    seen = set()
    sarif_results = []

    for finding in findings:
        rule_id, message = RULES.get(finding.category, ("PA999", finding.category))
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": finding.category,
                    "shortDescription": {"text": message},
                    "properties": {"tags": [finding.status, finding.confidence]},
                }
            )
        sarif_results.append(_sarif_result(finding, rule_id, message))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pwn-agent",
                        "informationUri": "https://github.com/snozzz/pwn-agent",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _sarif_result(finding: ClassifiedFinding, rule_id: str, message: str) -> dict:
    return {
        "ruleId": rule_id,
        "level": _level(finding.severity),
        "message": {"text": f"{message}: {finding.line_text}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number},
                }
            }
        ],
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "score": finding.score,
        },
    }


def write_sarif(path: Path, result: ScanResult, verified_signal: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sarif_dict(result, verified_signal=verified_signal), indent=2), encoding="utf-8")
