"""Analysis providers used by the scanner agent.

- RuleProvider: deterministic regex rules. Runs offline and is the default.
- BedrockProvider: sends the condensed context to a model on Amazon Bedrock (Converse API) and parses
  JSON findings. Its output goes through the same validator as the rules, so unsupported findings
  are dropped.
"""
import json
import os
import re

from .rules import RULES, RULES_BY_ID


class RuleProvider:
    name = "rules"

    def analyze(self, context, notes=""):
        chunk_code = "\n".join(context.chunk.code_lines.values())
        findings = []
        for line_no, code in context.lines.items():
            for rule in RULES:
                if rule.unless_in_chunk and any(s in chunk_code for s in rule.unless_in_chunk):
                    continue
                if rule.matches(code):
                    findings.append({
                        "rule_id": rule.id, "line": line_no, "evidence": code.strip(),
                        "message": rule.title, "source": self.name,
                    })
        return findings


SYSTEM_PROMPT = """You are a Java security reviewer. You receive a condensed slice of one Java method.
Each line is prefixed with its real line number, like "L42: code".
Report only vulnerabilities you can point to on a specific line shown to you.
Allowed rule_id values: {rules}.
Respond with only a JSON array. Each item: {{"rule_id": str, "line": int, "evidence": str, "message": str}}.
"evidence" must be copied exactly from the line. Return [] if nothing is vulnerable."""


class BedrockProvider:
    name = "bedrock"

    def __init__(self, model_id=None, region=None, client=None):
        self.model_id = model_id or os.environ.get("BEDROCK_MODEL_ID")
        if not self.model_id:
            raise ValueError("Set BEDROCK_MODEL_ID or pass --model-id to use the Bedrock provider.")
        if client is None:
            import boto3
            client = boto3.client("bedrock-runtime", region_name=region or os.environ.get("AWS_REGION", "us-east-1"))
        self.client = client
        rule_list = ", ".join(f"{r.id} ({r.title}, {r.cwe})" for r in RULES)
        self.system = SYSTEM_PROMPT.format(rules=rule_list)

    def analyze(self, context, notes=""):
        prompt = f"File: {context.chunk.file}\nMethod: {context.chunk.name}\n"
        if notes:
            prompt += f"Already reported in this file (do not repeat):\n{notes}\n"
        prompt += f"\nCode:\n{context.render()}"
        response = self.client.converse(
            modelId=self.model_id,
            system=[{"text": self.system}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )
        text = "".join(part.get("text", "") for part in response["output"]["message"]["content"])
        return [dict(item, source=self.name) for item in parse_json_findings(text)]


def parse_json_findings(text):
    """Extract a JSON array of findings from model output; tolerate surrounding prose or code fences."""
    match = re.search(r"\[.*\]", text, re.S)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    return [d for d in data if isinstance(d, dict)]


def get_provider(name, **kwargs):
    if name == "rules":
        return RuleProvider()
    if name == "bedrock":
        return BedrockProvider(**kwargs)
    raise ValueError(f"Unknown provider {name!r}")


__all__ = ["RuleProvider", "BedrockProvider", "get_provider", "parse_json_findings", "RULES_BY_ID"]
