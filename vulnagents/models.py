from dataclasses import asdict, dataclass, field


def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 characters per token), good enough for budgeting."""
    return max(1, len(text) // 4) if text else 0


@dataclass
class Chunk:
    """A bounded unit of work: one method (or the class-level code) in one file."""
    file: str
    start_line: int
    end_line: int
    name: str
    lines: dict  # line number -> original source line
    code_lines: dict  # line number -> source line with comments blanked out

    @property
    def text(self) -> str:
        return "\n".join(self.lines[n] for n in sorted(self.lines))

    @property
    def id(self) -> str:
        return f"{self.file}:{self.start_line}-{self.end_line}"


@dataclass
class Context:
    """The condensed slice of a chunk that is actually sent to the scanner."""
    chunk: Chunk
    lines: dict  # line number -> code line (comments removed)
    tokens_before: int
    tokens_after: int

    def render(self) -> str:
        return "\n".join(f"L{n}: {self.lines[n].strip()}" for n in sorted(self.lines))


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    evidence: str
    message: str
    severity: str = "medium"
    cwe: str = ""
    source: str = "rules"  # which provider produced it

    @property
    def key(self):
        return (self.file, self.line, self.rule_id)

    def to_dict(self):
        return asdict(self)


@dataclass
class Rejection:
    finding: dict
    reason: str


@dataclass
class Fix:
    rule_id: str
    file: str
    line: int
    original: str
    replacement: str
    imports: list = field(default_factory=list)
    status: str = "proposed"  # proposed | applied | rejected
    note: str = ""

    def to_dict(self):
        return asdict(self)
