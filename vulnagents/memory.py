"""Shared memory that agents read and write, with a token budget."""
from dataclasses import dataclass

from .models import estimate_tokens


@dataclass
class Entry:
    key: str
    kind: str  # "context" (raw chunk context) | "finding" | "summary"
    text: str
    file: str = ""

    @property
    def tokens(self):
        return estimate_tokens(self.text)


class SharedMemory:
    def __init__(self, budget_tokens: int = 1500):
        self.budget_tokens = budget_tokens
        self.entries: dict = {}
        self.peak_tokens = 0
        self.evicted_tokens = 0

    def put(self, entry: Entry):
        self.entries[entry.key] = entry
        self.peak_tokens = max(self.peak_tokens, self.total_tokens)

    def remove(self, key: str):
        entry = self.entries.pop(key, None)
        if entry:
            self.evicted_tokens += entry.tokens

    @property
    def total_tokens(self):
        return sum(e.tokens for e in self.entries.values())

    def of_kind(self, kind, file=None):
        return [e for e in self.entries.values() if e.kind == kind and (file is None or e.file == file)]

    def notes_for(self, file: str) -> str:
        """Compact notes about what was already found in this file (passed to LLM providers)."""
        parts = [e.text for e in self.of_kind("summary", file)] + [e.text for e in self.of_kind("finding", file)]
        return "\n".join(parts)
