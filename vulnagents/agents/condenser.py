"""Concise-information agent: keeps only the lines relevant to security analysis.

Large chunks hurt model accuracy, so instead of sending a whole method, this agent sends the
method signature plus lines containing security-relevant signals and one line of context around each.
Chunks with no signals are skipped entirely.
"""
from ..models import Context, estimate_tokens
from ..rules import SIGNAL_KEYWORDS


class ConciseInfoAgent:
    name = "concise-info"

    def __init__(self, window: int = 1):
        self.window = window

    def condense(self, chunk) -> Context:
        code = chunk.code_lines
        hits = [n for n, line in code.items() if any(k in line for k in SIGNAL_KEYWORDS)]
        keep = set()
        for n in hits:
            for m in range(n - self.window, n + self.window + 1):
                if m in code and code[m].strip():
                    keep.add(m)
        if keep and chunk.name != "<class-level>":
            keep.add(chunk.start_line)  # method signature
        lines = {n: code[n] for n in sorted(keep)}
        raw = "\n".join(code.values())
        kept = "\n".join(lines.values())
        return Context(chunk=chunk, lines=lines, tokens_before=estimate_tokens(raw), tokens_after=estimate_tokens(kept))
