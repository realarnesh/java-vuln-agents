"""Vulnerability rules. Each rule has regex patterns and optional automatic fix logic."""
import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Rule:
    id: str
    cwe: str
    severity: str
    title: str
    patterns: list
    guidance: str
    # If any of these appear anywhere in the chunk, the rule does not fire (e.g. XXE hardening).
    unless_in_chunk: list = field(default_factory=list)
    autofix: Optional[Callable[[str], Optional[str]]] = None
    fix_imports: list = field(default_factory=list)

    def matches(self, code_line: str) -> bool:
        return any(p.search(code_line) for p in self.patterns)


def _re(pattern, flags=0):
    return re.compile(pattern, flags)


def _fix_weak_hash(line):
    new = re.sub(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1|MD2)"\s*\)', 'MessageDigest.getInstance("SHA-256")', line, flags=re.I)
    return new if new != line else None


def _fix_weak_random(line):
    new = re.sub(r"\bnew\s+Random\s*\(", "new SecureRandom(", line)
    new = re.sub(r"(^|[\s(,<])Random(\s+\w+\s*=)", r"\1SecureRandom\2", new)
    return new if new != line else None


_SECRET_NAME = r"(?:password|passwd|pwd|secret|api_?key|access_?key|token)"
# Only a plain literal assignment counts; "prefix" + runtimeValue is not a hard-coded secret.
_SECRET_ASSIGN = _re(rf'\b(\w*{_SECRET_NAME}\w*)\s*=\s*"([^"]{{4,}})"(?=\s*[;,)])', re.I)


def _fix_secret(line):
    m = _SECRET_ASSIGN.search(line)
    if not m:
        return None
    name = m.group(1)
    env = name if name.isupper() else re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).upper()
    return line[: m.start()] + f'{m.group(1)} = System.getenv("{env}")' + line[m.end():]


RULES = [
    Rule(
        "SQLI", "CWE-89", "high", "SQL injection",
        [
            _re(r'"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+', re.I),
            _re(r"\.(executeQuery|executeUpdate|execute|addBatch|prepareStatement)\s*\([^)]*\"\s*\+"),
        ],
        "Use a PreparedStatement with ? placeholders and bind values with setString/setInt instead of "
        "concatenating input into SQL.",
    ),
    Rule(
        "CMDI", "CWE-78", "high", "OS command injection",
        [
            _re(r"Runtime\.getRuntime\(\)\.exec\(\s*[^\"\s)][^)]*\)"),
            _re(r"Runtime\.getRuntime\(\)\.exec\([^)]*\+"),
            _re(r"new\s+ProcessBuilder\([^)]*\+"),
        ],
        "Avoid passing user input to a shell. Use ProcessBuilder with a fixed command and an allow-listed, "
        "separately passed argument list.",
    ),
    Rule(
        "PATH", "CWE-22", "medium", "Path traversal",
        [_re(r"new\s+(File|FileInputStream|FileReader|FileOutputStream)\s*\([^)]*\+"), _re(r"Paths\.get\([^)]*\+")],
        "Resolve the path against a fixed base directory, normalize it, and reject it if it escapes the base "
        "(e.g. base.resolve(name).normalize().startsWith(base)).",
    ),
    Rule(
        "SECRET", "CWE-798", "high", "Hard-coded credential",
        [_SECRET_ASSIGN],
        "Load secrets from environment variables or a secrets manager instead of source code.",
        autofix=_fix_secret,
    ),
    Rule(
        "WEAK_HASH", "CWE-328", "medium", "Weak hash algorithm",
        [_re(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1|MD2)"\s*\)', re.I)],
        "Use SHA-256 or stronger. For passwords, use a slow KDF such as bcrypt, scrypt, or PBKDF2.",
        autofix=_fix_weak_hash,
    ),
    Rule(
        "WEAK_CIPHER", "CWE-327", "high", "Broken or risky cipher",
        [_re(r'Cipher\.getInstance\(\s*"(DES|DESede|RC4|Blowfish|AES|AES/ECB[^"]*)"\s*\)', re.I)],
        "Use AES/GCM/NoPadding with a random 12-byte IV per message. This needs IV handling, so it is not "
        "auto-fixed.",
    ),
    Rule(
        "WEAK_RANDOM", "CWE-330", "low", "Insecure random number generator",
        [_re(r"\bnew\s+Random\s*\(")],
        "Use java.security.SecureRandom for tokens, IDs, and anything security-sensitive.",
        autofix=_fix_weak_random,
        fix_imports=["java.security.SecureRandom"],
    ),
    Rule(
        "DESER", "CWE-502", "high", "Unsafe deserialization",
        [_re(r"new\s+ObjectInputStream\s*\(")],
        "Do not deserialize untrusted data. Use a data format like JSON, or apply an ObjectInputFilter allow-list.",
    ),
    Rule(
        "XXE", "CWE-611", "high", "XML external entity (XXE)",
        [_re(r"DocumentBuilderFactory\.newInstance\(\)"), _re(r"SAXParserFactory\.newInstance\(\)")],
        'Disable DTDs: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true).',
        unless_in_chunk=["disallow-doctype-decl", "FEATURE_SECURE_PROCESSING"],
    ),
]

RULES_BY_ID = {r.id: r for r in RULES}

# Keywords the concise-information agent uses to decide which lines are worth sending to the scanner.
SIGNAL_KEYWORDS = [
    "execute", "prepareStatement", "addBatch", "SELECT", "INSERT", "UPDATE", "DELETE", "select ", "insert ",
    "update ", "delete ", "Runtime", "exec(", "ProcessBuilder", "File", "Paths.get", "MessageDigest", "Cipher",
    "Random", "ObjectInputStream", "readObject", "DocumentBuilderFactory", "SAXParserFactory", "setFeature",
    "password", "Password", "PASSWORD", "secret", "Secret", "SECRET", "apiKey", "api_key", "API_KEY", "token",
    "Token", "TOKEN", "accessKey", "ACCESS_KEY", "pwd", "passwd",
]
