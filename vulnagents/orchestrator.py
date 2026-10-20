"""Orchestrator: runs the agents over each bounded task and assembles the report."""
from dataclasses import dataclass, field
from pathlib import Path

from .agents.condenser import ConciseInfoAgent
from .agents.gc import GarbageCollectorAgent
from .agents.partitioner import PartitionerAgent
from .agents.remediator import RemediationAgent
from .agents.scanner import ScannerAgent
from .agents.validator import ValidatorAgent
from .memory import Entry, SharedMemory
from .providers import RuleProvider


@dataclass
class Report:
    findings: list = field(default_factory=list)
    rejected: list = field(default_factory=list)
    fixes: list = field(default_factory=list)
    patched: dict = field(default_factory=dict)  # file -> patched source
    metrics: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "metrics": self.metrics,
            "findings": [f.to_dict() for f in self.findings],
            "fixes": [f.to_dict() for f in self.fixes],
            "rejected": [{"finding": r.finding, "reason": r.reason} for r in self.rejected],
        }


class Orchestrator:
    def __init__(self, provider=None, max_chunk_lines=60, memory_budget_tokens=1500):
        self.provider = provider or RuleProvider()
        self.partitioner = PartitionerAgent(max_lines=max_chunk_lines)
        self.condenser = ConciseInfoAgent()
        self.scanner = ScannerAgent(self.provider)
        self.remediator = RemediationAgent()
        self.gc = GarbageCollectorAgent()
        self.memory_budget_tokens = memory_budget_tokens

    def scan_paths(self, paths, fix=False, root=None):
        files = self.partitioner.collect_files(paths)
        base = Path(root) if root else None
        sources = {}
        for f in files:
            name = str(f.relative_to(base)) if base and f.is_relative_to(base) else str(f)
            sources[name] = f.read_text(encoding="utf-8", errors="replace")
        return self.scan_sources(sources, fix=fix)

    def scan_sources(self, sources: dict, fix=False):
        report = Report()
        memory = SharedMemory(self.memory_budget_tokens)
        validator = ValidatorAgent()
        stats = dict(files=len(sources), chunks=0, chunks_skipped=0, tokens_raw=0, tokens_sent=0, provider=self.provider.name)

        for file, source in sources.items():
            for chunk in self.partitioner.partition_source(source, file):
                stats["chunks"] += 1
                context = self.condenser.condense(chunk)
                stats["tokens_raw"] += context.tokens_before
                if not context.lines:
                    stats["chunks_skipped"] += 1
                    continue
                stats["tokens_sent"] += context.tokens_after
                memory.put(Entry(key=f"context:{chunk.id}", kind="context", text=context.render(), file=file))

                raw = self.scanner.scan(context, notes=memory.notes_for(file))
                accepted, rejected = validator.validate_findings(raw, chunk)
                report.findings += accepted
                report.rejected += rejected
                for f in accepted:
                    memory.put(Entry(key=f"finding:{file}:{f.line}:{f.rule_id}", kind="finding",
                                     text=f"{f.rule_id} line {f.line}", file=file))
                self.gc.collect(memory, chunk.id)

        report.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
        if fix:
            self._remediate(report, sources)

        stats.update(
            findings=len(report.findings), rejected=len(report.rejected),
            fixes_applied=sum(f.status == "applied" for f in report.fixes),
            peak_memory_tokens=memory.peak_tokens, memory_budget_tokens=memory.budget_tokens,
            evicted_tokens=memory.evicted_tokens,
            context_reduction_pct=round(100 * (1 - stats["tokens_sent"] / stats["tokens_raw"]), 1) if stats["tokens_raw"] else 0.0,
        )
        report.metrics = stats
        return report

    def _detect(self, source, file="<patched>"):
        """Rule-based rescan used to confirm a fix removed its finding."""
        found = set()
        provider = RuleProvider()
        for chunk in self.partitioner.partition_source(source, file):
            context = self.condenser.condense(chunk)
            for raw in provider.analyze(context):
                found.add((raw["line"], raw["rule_id"]))
        return found

    def _remediate(self, report, sources):
        by_file = {}
        for finding in report.findings:
            original = sources[finding.file].splitlines()[finding.line - 1]
            by_file.setdefault(finding.file, []).append(self.remediator.propose(finding, original))
        for file, fixes in by_file.items():
            patched = self.remediator.apply(sources[file], fixes, self._detect)
            if patched != sources[file]:
                report.patched[file] = patched
            report.fixes += fixes
