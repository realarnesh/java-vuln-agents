"""Partitioner agent: splits a codebase into bounded, method-sized tasks."""
import re
from pathlib import Path

from ..javasource import find_block_end, strip_comments
from ..models import Chunk

METHOD_START = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)*"
    r"(?:<[^>]+>\s*)?[\w<>\[\],.? ]+\s+(\w+)\s*\([^;{]*\)?\s*(?:throws\s+[\w.,\s]+?)?\s*(?:\{.*)?$"
)
CONSTRUCTOR_START = re.compile(r"^\s*(?:public|protected|private)\s+([A-Z]\w*)\s*\([^;{]*\)?[^;{]*(?:\{.*)?$")
CONTROL = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else", "try", "do"}


class PartitionerAgent:
    name = "partitioner"

    def __init__(self, max_lines: int = 60):
        self.max_lines = max_lines

    def collect_files(self, paths):
        files = []
        for p in map(Path, paths):
            if p.is_dir():
                files += sorted(p.rglob("*.java"))
            elif p.suffix == ".java":
                files.append(p)
        return files

    def partition_file(self, path: Path, display_name: str = None):
        source = path.read_text(encoding="utf-8", errors="replace")
        return self.partition_source(source, display_name or str(path))

    def partition_source(self, source: str, file: str):
        original = source.splitlines()
        code = strip_comments(source).splitlines()
        code += [""] * (len(original) - len(code))
        chunks, covered, i = [], set(), 0
        while i < len(code):
            name = self._method_name(code, i)
            if name:
                end = find_block_end(code, i)
                chunks += self._make_chunks(file, name, i, end, original, code)
                covered.update(range(i, end + 1))
                i = end + 1
            else:
                i += 1
        # Everything outside methods (imports, fields, initializers) becomes class-level chunks.
        rest = [n for n in range(len(code)) if n not in covered and code[n].strip()]
        for start in range(0, len(rest), self.max_lines):
            block = rest[start:start + self.max_lines]
            chunks.append(self._chunk(file, "<class-level>", block, original, code))
        return sorted(chunks, key=lambda c: c.start_line)

    def _method_name(self, code, i):
        line = code[i]
        if "(" not in line or line.strip().endswith(";") and "{" not in line:
            return None
        for regex in (METHOD_START, CONSTRUCTOR_START):
            m = regex.match(line)
            if m and m.group(1) not in CONTROL:
                lookahead = " ".join(code[i:i + 3])
                if "{" in lookahead:
                    return m.group(1)
        return None

    def _make_chunks(self, file, name, start, end, original, code):
        indices = list(range(start, end + 1))
        if len(indices) <= self.max_lines:
            return [self._chunk(file, name, indices, original, code)]
        parts = []
        for k in range(0, len(indices), self.max_lines):
            parts.append(self._chunk(file, f"{name}[part {k // self.max_lines + 1}]", indices[k:k + self.max_lines], original, code))
        return parts

    @staticmethod
    def _chunk(file, name, indices, original, code):
        return Chunk(
            file=file,
            start_line=indices[0] + 1,
            end_line=indices[-1] + 1,
            name=name,
            lines={n + 1: original[n] for n in indices},
            code_lines={n + 1: code[n] for n in indices},
        )
