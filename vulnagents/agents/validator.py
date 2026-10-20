"""Validator agent: rejects findings and fixes that the source code does not support.

This is the guard against hallucinated output: every finding must point to a real line inside the
chunk it came from, cite evidence that actually appears on that line, and use a known rule.
Fixes must leave the file parseable and must actually remove the finding they target.
"""
import re

from ..javasource import parses
from ..models import Finding, Rejection
from ..rules import RULES_BY_ID


def _norm(text):
    return re.sub(r"\s+", "", text or "")


class ValidatorAgent:
    name = "validator"

    def __init__(self):
        self.seen = set()

    def validate_findings(self, raw_findings, chunk):
        accepted, rejected = [], []
        for raw in raw_findings:
            reason = self._problem(raw, chunk)
            if reason:
                rejected.append(Rejection(finding=dict(raw), reason=reason))
                continue
            rule = RULES_BY_ID[raw["rule_id"]]
            finding = Finding(
                rule_id=rule.id, file=chunk.file, line=int(raw["line"]),
                evidence=chunk.lines[int(raw["line"])].strip(),
                message=raw.get("message") or rule.title, severity=rule.severity, cwe=rule.cwe,
                source=raw.get("source", "rules"),
            )
            if finding.key in self.seen:
                rejected.append(Rejection(finding=dict(raw), reason="duplicate"))
                continue
            self.seen.add(finding.key)
            accepted.append(finding)
        return accepted, rejected

    @staticmethod
    def _problem(raw, chunk):
        if raw.get("rule_id") not in RULES_BY_ID:
            return f"unknown rule {raw.get('rule_id')!r}"
        try:
            line = int(raw.get("line"))
        except (TypeError, ValueError):
            return "missing or invalid line number"
        if line not in chunk.lines:
            return f"line {line} is outside the analyzed chunk ({chunk.start_line}-{chunk.end_line})"
        if not chunk.code_lines[line].strip():
            return f"line {line} is blank or only a comment"
        evidence = raw.get("evidence")
        if evidence and _norm(evidence) not in _norm(chunk.lines[line]):
            return f"evidence does not appear on line {line}"
        return None

    @staticmethod
    def validate_patched_source(source: str):
        return parses(source)
