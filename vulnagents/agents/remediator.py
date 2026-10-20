"""Remediation agent: proposes fixes, applies the safe ones, and keeps only fixes that validate."""
import re

from ..javasource import parses
from ..models import Fix
from ..rules import RULES_BY_ID


class RemediationAgent:
    name = "remediator"

    def propose(self, finding, original_line: str):
        rule = RULES_BY_ID[finding.rule_id]
        replacement = rule.autofix(original_line) if rule.autofix else None
        if replacement is None:
            return Fix(finding.rule_id, finding.file, finding.line, original_line, original_line,
                       status="manual", note=rule.guidance)
        return Fix(finding.rule_id, finding.file, finding.line, original_line, replacement,
                   imports=list(rule.fix_imports), note=rule.guidance)

    def apply(self, source: str, fixes, rescan):
        """Apply fixes one at a time. Keep a fix only if the file still parses and the finding is gone.

        rescan(source) -> set of (line, rule_id) currently detected in the source.
        """
        lines = source.splitlines()
        trailing_newline = source.endswith("\n")
        offset = 0  # lines inserted by imports shift later line numbers
        for fix in sorted(fixes, key=lambda f: f.line):
            if fix.status == "manual":
                continue
            candidate = list(lines)
            target = fix.line - 1 + offset
            if candidate[target] != fix.original:
                fix.status, fix.note = "rejected", "source line changed before fix could be applied"
                continue
            candidate[target] = fix.replacement
            added = self._add_imports(candidate, fix.imports)
            new_source = "\n".join(candidate) + ("\n" if trailing_newline else "")
            ok, error = parses(new_source)
            if not ok:
                fix.status, fix.note = "rejected", f"patched file no longer parses ({error})"
                continue
            if (fix.line + offset + added, fix.rule_id) in rescan(new_source):
                fix.status, fix.note = "rejected", "finding still present after fix"
                continue
            lines, offset = candidate, offset + added
            fix.status = "applied"
        return "\n".join(lines) + ("\n" if trailing_newline else "")

    @staticmethod
    def _add_imports(lines, imports):
        added = 0
        for imp in imports:
            stmt = f"import {imp};"
            if any(line.strip() == stmt for line in lines):
                continue
            idx = 0
            for i, line in enumerate(lines):
                if re.match(r"\s*(package|import)\s", line):
                    idx = i + 1
            lines.insert(idx, stmt)
            added += 1
        return added
