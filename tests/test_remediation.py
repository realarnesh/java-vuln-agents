from vulnagents.javasource import parses
from vulnagents.models import Fix
from vulnagents.agents.remediator import RemediationAgent
from vulnagents.orchestrator import Orchestrator

SOURCE = """package demo;

import java.security.MessageDigest;
import java.util.Random;

public class C {
    private static final String DB_PASSWORD = "hunter2!!";
    private String apiKey = "abcd1234";

    byte[] h(byte[] d) throws Exception {
        return MessageDigest.getInstance("MD5").digest(d);
    }

    long r() {
        Random random = new Random();
        return random.nextLong();
    }
}
"""


def test_applies_validated_fixes_and_removes_findings():
    orchestrator = Orchestrator()
    report = orchestrator.scan_sources({"C.java": SOURCE}, fix=True)
    assert {f.rule_id for f in report.findings} == {"SECRET", "WEAK_HASH", "WEAK_RANDOM"}
    assert all(f.status == "applied" for f in report.fixes)

    patched = report.patched["C.java"]
    assert parses(patched)[0]
    assert 'System.getenv("DB_PASSWORD")' in patched
    assert 'System.getenv("API_KEY")' in patched
    assert 'getInstance("SHA-256")' in patched
    assert "SecureRandom random = new SecureRandom();" in patched
    assert "import java.security.SecureRandom;" in patched
    assert orchestrator.scan_sources({"C.java": patched}).findings == []


def test_rejects_fix_that_breaks_parsing():
    fix = Fix("WEAK_HASH", "C.java", 11, '        return MessageDigest.getInstance("MD5").digest(d);',
              '        return MessageDigest.getInstance("SHA-256".digest(d);')
    out = RemediationAgent().apply(SOURCE, [fix], rescan=lambda s: set())
    assert fix.status == "rejected" and "no longer parses" in fix.note
    assert out == SOURCE


def test_rejects_fix_that_does_not_remove_the_finding():
    line = '        return MessageDigest.getInstance("MD5").digest(d);'
    fix = Fix("WEAK_HASH", "C.java", 11, line, line.replace("digest(d)", "digest(d) "))
    RemediationAgent().apply(SOURCE, [fix], rescan=Orchestrator()._detect)
    assert fix.status == "rejected" and fix.note == "finding still present after fix"


def test_risky_rules_are_left_for_manual_review():
    source = 'class D { void m(String x) throws Exception { Runtime.getRuntime().exec("ls " + x); } }\n'
    report = Orchestrator().scan_sources({"D.java": source}, fix=True)
    assert [f.status for f in report.fixes] == ["manual"]
    assert report.patched == {}
