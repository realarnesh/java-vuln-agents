"""Small helpers for working with Java source text."""


def strip_comments(source: str) -> str:
    """Blank out // and /* */ comments while preserving line numbers and string literals."""
    out, i, n = [], 0, len(source)
    in_block = in_line = in_str = in_char = False
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_block:
            if c == "*" and nxt == "/":
                out.append("  "); i += 2; in_block = False; continue
            out.append("\n" if c == "\n" else " ")
        elif in_line:
            if c == "\n":
                out.append(c); in_line = False
            else:
                out.append(" ")
        elif in_str:
            out.append(c)
            if c == "\\":
                out.append(nxt); i += 2; continue
            if c == '"':
                in_str = False
        elif in_char:
            out.append(c)
            if c == "\\":
                out.append(nxt); i += 2; continue
            if c == "'":
                in_char = False
        else:
            if c == "/" and nxt == "/":
                in_line = True; out.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                in_block = True; out.append("  "); i += 2; continue
            if c == '"':
                in_str = True
            elif c == "'":
                in_char = True
            out.append(c)
        i += 1
    return "".join(out)


def find_block_end(code_lines: list, start_index: int) -> int:
    """Given 0-based index of a line where a block starts, return index of its closing brace line."""
    depth, opened = 0, False
    for idx in range(start_index, len(code_lines)):
        line, in_str = code_lines[idx], False
        for j, ch in enumerate(line):
            if ch == '"' and (j == 0 or line[j - 1] != "\\"):
                in_str = not in_str
            if in_str:
                continue
            if ch == "{":
                depth += 1; opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth == 0:
                    return idx
        if not opened and line.rstrip().endswith(";"):
            return idx  # abstract / interface method with no body
    return len(code_lines) - 1


def parses(source: str) -> tuple:
    """Return (ok, error message) for whether the Java source parses."""
    import javalang
    try:
        javalang.parse.parse(source)
        return True, ""
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as exc:
        return False, f"{type(exc).__name__}: {getattr(exc, 'description', exc)}"
    except Exception as exc:  # javalang raises a few other types on bad input
        return False, f"{type(exc).__name__}: {exc}"
