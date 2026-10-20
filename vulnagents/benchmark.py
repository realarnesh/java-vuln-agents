"""Measure precision and recall against samples marked with `// expect: RULE_ID` comments.

Usage: python -m vulnagents.benchmark [samples_dir]
"""
import re
import sys
from pathlib import Path

from .orchestrator import Orchestrator

EXPECT = re.compile(r"//\s*expect:\s*([A-Z_]+)")


def expected_findings(root: Path):
    expected = set()
    for path in sorted(root.rglob("*.java")):
        rel = str(path.relative_to(root))
        for n, line in enumerate(path.read_text().splitlines(), start=1):
            m = EXPECT.search(line)
            if m:
                expected.add((rel, n, m.group(1)))
    return expected


def run(root="samples", orchestrator=None):
    root = Path(root)
    orchestrator = orchestrator or Orchestrator()
    report = orchestrator.scan_paths([root], root=root)
    actual = {f.key for f in report.findings}
    expected = expected_findings(root)
    tp = actual & expected
    precision = len(tp) / len(actual) if actual else 1.0
    recall = len(tp) / len(expected) if expected else 1.0
    return {
        "expected": len(expected), "found": len(actual), "true_positives": len(tp),
        "precision": round(precision, 3), "recall": round(recall, 3),
        "false_positives": sorted(actual - expected), "missed": sorted(expected - actual),
    }


if __name__ == "__main__":
    result = run(sys.argv[1] if len(sys.argv) > 1 else "samples")
    print(f"expected={result['expected']} found={result['found']} "
          f"precision={result['precision']} recall={result['recall']}")
    for fp in result["false_positives"]:
        print("  false positive:", fp)
    for miss in result["missed"]:
        print("  missed:", miss)
    sys.exit(0 if result["precision"] == 1.0 and result["recall"] == 1.0 else 1)
