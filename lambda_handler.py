"""AWS Lambda entry point.

Event: {"files": {"src/Foo.java": "<source>", ...}, "fix": false}
Set PROVIDER=bedrock and BEDROCK_MODEL_ID to use a Bedrock model; defaults to the rule provider.
"""
import json
import os

from vulnagents.orchestrator import Orchestrator
from vulnagents.providers import get_provider


def handler(event, context=None):
    if isinstance(event.get("body"), str):  # API Gateway proxy integration
        event = json.loads(event["body"])
    files = event.get("files")
    if not isinstance(files, dict) or not files:
        return {"statusCode": 400, "body": json.dumps({"error": "Provide 'files' as {path: source}."})}
    provider = get_provider(os.environ.get("PROVIDER", "rules"))
    report = Orchestrator(provider=provider).scan_sources(files, fix=bool(event.get("fix")))
    body = report.to_dict()
    if event.get("fix"):
        body["patched"] = report.patched
    return {"statusCode": 200, "body": json.dumps(body)}
