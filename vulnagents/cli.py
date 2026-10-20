import argparse
import sys
from pathlib import Path

from . import report as fmt
from .orchestrator import Orchestrator
from .providers import get_provider


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vulnagents", description="Multi-agent Java vulnerability scanner")
    parser.add_argument("paths", nargs="+", help="Java files or directories to scan")
    parser.add_argument("--provider", choices=["rules", "bedrock"], default="rules")
    parser.add_argument("--model-id", help="Bedrock model ID (or set BEDROCK_MODEL_ID)")
    parser.add_argument("--format", choices=["text", "json", "md"], default="text")
    parser.add_argument("--fix", action="store_true", help="propose and apply validated fixes")
    parser.add_argument("--out", help="directory to write patched files (requires --fix); sources are never modified in place")
    parser.add_argument("--report", help="also write the report to this file")
    parser.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never",
                        help="exit with status 1 if a finding at or above this severity exists")
    args = parser.parse_args(argv)

    kwargs = {"model_id": args.model_id} if args.provider == "bedrock" else {}
    orchestrator = Orchestrator(provider=get_provider(args.provider, **kwargs))
    roots = [Path(p) for p in args.paths]
    root = roots[0] if len(roots) == 1 and roots[0].is_dir() else None
    result = orchestrator.scan_paths(args.paths, fix=args.fix, root=root)

    output = {"text": fmt.to_text, "json": fmt.to_json, "md": fmt.to_markdown}[args.format](result)
    print(output)
    if args.report:
        Path(args.report).write_text(output, encoding="utf-8")
    if args.fix and args.out:
        for file, source in result.patched.items():
            target = Path(args.out) / (file if root else Path(file).name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        print(f"\nWrote {len(result.patched)} patched file(s) to {args.out}", file=sys.stderr)

    if args.fail_on != "never":
        threshold = fmt.SEVERITY_ORDER[args.fail_on]
        if any(fmt.SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
