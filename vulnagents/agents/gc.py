"""Garbage-collector agent: keeps shared memory small between tasks.

After each chunk, the raw context is evicted (only the accepted findings matter downstream).
If memory still exceeds its budget, older per-finding notes for a file are folded into a one-line
summary. This bounds how much text later model calls receive, however large the project is.
"""
from collections import Counter

from ..memory import Entry


class GarbageCollectorAgent:
    name = "garbage-collector"

    def collect(self, memory, finished_chunk_id: str):
        memory.remove(f"context:{finished_chunk_id}")
        if memory.total_tokens <= memory.budget_tokens:
            return
        files = Counter(e.file for e in memory.of_kind("finding"))
        for file, _ in files.most_common():
            findings = memory.of_kind("finding", file)
            counts = Counter(e.text.split()[0] for e in findings)
            for e in findings:
                memory.remove(e.key)
            prior = memory.entries.pop(f"summary:{file}", None)
            if prior:
                for part in prior.text.split(": ", 1)[1].split(", "):
                    rule, n = part.rsplit("x", 1)
                    counts[rule] += int(n)
            summary = f"{file}: " + ", ".join(f"{r}x{n}" for r, n in sorted(counts.items()))
            memory.put(Entry(key=f"summary:{file}", kind="summary", text=summary, file=file))
            if memory.total_tokens <= memory.budget_tokens:
                return
