from pathlib import Path

from vulnagents.benchmark import run
from vulnagents.orchestrator import Orchestrator

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_finds_every_known_vulnerability_with_no_false_positives():
    result = run(SAMPLES)
    assert result["missed"] == []
    assert result["false_positives"] == []
    assert result["expected"] == 12


def test_safe_samples_produce_no_findings():
    report = Orchestrator().scan_paths([SAMPLES / "safe"])
    assert report.findings == []


def test_commented_out_code_is_ignored():
    source = """
public class A {
    void m(String id) {
        // stmt.executeQuery("SELECT * FROM t WHERE id = " + id);
        /* Runtime.getRuntime().exec("rm " + id); */
    }
}
"""
    assert Orchestrator().scan_sources({"A.java": source}).findings == []


def test_runtime_built_values_are_not_hardcoded_secrets():
    source = 'class K { void m() { String apiKey = "API_KEY=" + java.util.UUID.randomUUID(); } }\n'
    assert Orchestrator().scan_sources({"K.java": source}).findings == []
