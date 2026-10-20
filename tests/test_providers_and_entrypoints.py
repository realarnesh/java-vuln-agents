import json
from pathlib import Path

import pytest

import lambda_handler
from vulnagents.cli import main
from vulnagents.orchestrator import Orchestrator
from vulnagents.providers import BedrockProvider, parse_json_findings

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
SOURCE = 'public class S {\n    void m(String id) throws Exception {\n        stmt.executeQuery("SELECT * FROM t WHERE id = " + id);\n    }\n}\n'


class FakeBedrock:
    """Stands in for boto3's bedrock-runtime client and records the prompts it receives."""

    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {"output": {"message": {"content": [{"text": self.reply}]}}}


def test_parse_json_findings_handles_code_fences_and_bad_output():
    assert parse_json_findings('```json\n[{"rule_id": "SQLI", "line": 3}]\n```') == [{"rule_id": "SQLI", "line": 3}]
    assert parse_json_findings("I could not find anything.") == []
    assert parse_json_findings("[not json") == []


def test_bedrock_provider_output_is_validated():
    reply = json.dumps([
        {"rule_id": "SQLI", "line": 3, "evidence": 'executeQuery("SELECT * FROM t WHERE id = " + id)', "message": "SQL injection"},
        {"rule_id": "SQLI", "line": 40, "evidence": "made up", "message": "hallucinated"},
    ])
    fake = FakeBedrock(reply)
    report = Orchestrator(provider=BedrockProvider(model_id="test-model", client=fake)).scan_sources({"S.java": SOURCE})

    assert [(f.rule_id, f.line, f.source) for f in report.findings] == [("SQLI", 3, "bedrock")]
    assert len(report.rejected) == 1 and "outside the analyzed chunk" in report.rejected[0].reason
    prompt = fake.calls[0]["messages"][0]["content"][0]["text"]
    assert "L3:" in prompt and fake.calls[0]["modelId"] == "test-model"


def test_bedrock_provider_requires_model_id(monkeypatch):
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    with pytest.raises(ValueError):
        BedrockProvider(client=FakeBedrock("[]"))


def test_lambda_handler_scans_and_fixes():
    event = {"files": {"C.java": 'class C { byte[] h(byte[] d) throws Exception { return java.security.MessageDigest.getInstance("MD5").digest(d); } }\n'}, "fix": True}
    response = lambda_handler.handler(event)
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["findings"][0]["rule_id"] == "WEAK_HASH"
    assert 'getInstance("SHA-256")' in body["patched"]["C.java"]


def test_lambda_handler_supports_api_gateway_and_rejects_bad_input():
    ok = lambda_handler.handler({"body": json.dumps({"files": {"S.java": SOURCE}})})
    assert json.loads(ok["body"])["findings"][0]["rule_id"] == "SQLI"
    assert lambda_handler.handler({"files": {}})["statusCode"] == 400


def test_cli_writes_patched_files_and_fails_on_high(tmp_path, capsys):
    out = tmp_path / "fixed"
    code = main([str(SAMPLES / "vulnerable"), "--fix", "--out", str(out), "--format", "md", "--fail-on", "high"])
    assert code == 1
    assert (out / "CryptoUtil.java").exists()
    assert "# Java Vulnerability Report" in capsys.readouterr().out
    assert main([str(SAMPLES / "safe"), "--fail-on", "low"]) == 0
