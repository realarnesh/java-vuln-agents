# java-vuln-agents

A small multi-agent pipeline that scans Java source for common vulnerabilities, proposes fixes, and applies only the fixes it can verify. Each agent does one job. The agents share a token-budgeted memory, so the context passed to the model stays bounded as the codebase grows.

It runs fully offline with a deterministic rule provider. The same pipeline can call a model on **AWS Bedrock** (Converse API), and a **Lambda** handler is included.

> This is a deliberately basic reference implementation. It is not a replacement for a production SAST tool such as Semgrep, CodeQL, or SpotBugs/Find Security Bugs.

## Architecture

```
 Java files
     │
     ▼
┌─────────────┐   method-sized tasks (class-level code becomes its own task)
│ Partitioner │──────────────────────────────────────────────┐
└─────────────┘                                              │
                                                             ▼
┌──────────────┐  signature + security-relevant lines   ┌─────────┐
│ Concise-Info │───────(tasks with no signals skipped)──▶│ Scanner │  RuleProvider | BedrockProvider
└──────────────┘                                        └────┬────┘
                                                             │ candidate findings (JSON)
                                                             ▼
                                                       ┌───────────┐
                                                       │ Validator │  rejects hallucinated findings
                                                       └─────┬─────┘
                                                             │
                     ┌───────────────────────────────────────┼───────────────────┐
                     ▼                                       ▼                   ▼
              ┌────────────┐                          ┌──────────────┐     ┌─────────┐
              │ Remediator │  fix → re-parse → rescan  │ Shared memory│◀───▶│ Garbage │
              └────────────┘  keep only if it passes  │ (token budget)│     │Collector│
                                                      └──────────────┘     └─────────┘
```

| Agent | Responsibility |
|---|---|
| **Partitioner** | Splits each file into method/constructor tasks using brace matching on comment- and string-stripped source. Fields and imports go into a class-level task. |
| **Concise-Info** | Keeps the method signature plus lines with security signals (`executeQuery`, `Runtime.exec`, `MessageDigest`, `ObjectInputStream`…) and one line of context around each. Tasks with no signals are skipped and never sent to the model. |
| **Scanner** | Sends the condensed context to a provider. `RuleProvider` uses regex and context rules. `BedrockProvider` sends the same context to a Bedrock model and parses its JSON findings. |
| **Validator** | Guards against hallucinated output. A finding must point to a real line inside its task, cite evidence that actually appears on that line, and use a known rule. Fixes must leave the file parseable (`javalang`) and must remove the finding they target on rescan. |
| **Remediator** | Applies automatic fixes where a safe mechanical rewrite exists and gives manual guidance otherwise. |
| **Garbage Collector** | Evicts raw context after each task. If memory is still over budget, it folds per-finding notes for a file into a one-line summary. |

## Rules

| ID | CWE | Severity | Detects | Autofix |
|---|---|---|---|---|
| `SQLI` | CWE-89 | high | String-concatenated SQL passed to `Statement` | guidance (use `PreparedStatement`) |
| `CMDI` | CWE-78 | high | `Runtime.exec` with non-literal or concatenated input; `ProcessBuilder` with concatenation | guidance |
| `PATH` | CWE-22 | medium | `File*` streams / `Paths.get` built by string concatenation | guidance |
| `SECRET` | CWE-798 | high | Credential-named variables assigned a string literal | `System.getenv("NAME")` |
| `WEAK_HASH` | CWE-328 | medium | `MessageDigest` with MD5 / SHA-1 | SHA-256 |
| `WEAK_CIPHER` | CWE-327 | high | DES, 3DES, RC4, Blowfish, AES/ECB, or bare `"AES"` (defaults to ECB) | guidance (AES/GCM) |
| `WEAK_RANDOM` | CWE-330 | low | `java.util.Random` | `SecureRandom` + import |
| `DESER` | CWE-502 | high | `ObjectInputStream.readObject` on untrusted data | guidance |
| `XXE` | CWE-611 | high | `DocumentBuilderFactory` without `disallow-doctype-decl` / secure processing | guidance |

## Quick start

```bash
pip install -r requirements-dev.txt

python -m vulnagents samples                          # text report
python -m vulnagents samples --format md --report report.md
python -m vulnagents samples --fix --out fixed/       # write patched copies; sources are never edited in place
python -m vulnagents src/ --fail-on high              # exit 1 if a high-severity finding exists (CI gate)
```

Sample output:

```
[HIGH  ] SECRET      vulnerable/CryptoUtil.java:9  private String apiKey = "sk_live_51HxExampleKey"; // expect: SECRET
[HIGH  ] WEAK_CIPHER vulnerable/CryptoUtil.java:25  return Cipher.getInstance("AES"); // expect: WEAK_CIPHER
[HIGH  ] CMDI        vulnerable/ReportService.java:17  return Runtime.getRuntime().exec("wkhtmltopdf " + reportName + " out.pdf"); // expect: CMDI
...
12 findings in 6 files | 27 tasks (3 skipped) | context 1048/1299 tokens (-19.3%) | peak memory 93/1500 | rejected 0
fixes applied: 5 of 12
```

### Using AWS Bedrock

```bash
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID=<a model ID enabled in your account>
python -m vulnagents samples --provider bedrock
```

The model receives only the condensed task context and must return JSON findings. Every finding still goes through the Validator, so a finding that cites a line or evidence not in the source is dropped and counted under `rejected`.

### AWS Lambda

`lambda_handler.handler` accepts a direct event or an API Gateway proxy body:

```json
{ "files": { "src/UserDao.java": "<java source>" }, "fix": true }
```

It returns the JSON report, plus the patched sources when `fix` is true. Set `PROVIDER=bedrock` and `BEDROCK_MODEL_ID` in the function environment to use a model. The default is the rule provider.

## Evaluation

`python -m vulnagents.benchmark` scans `samples/` and compares results against `// expect: RULE` markers in the source:

```
expected=12 found=12 precision=1.0 recall=1.0
```

These are small, hand-written samples, so the numbers check correctness only and are not a real-world accuracy claim. As a smoke test, I also ran the scanner on [OWASP WebGoat](https://github.com/WebGoat/WebGoat) (`src/main/java`, 334 files). It finished in under a second with 43 findings, mostly WebGoat's intentional SQL injection, hard-coded secrets, and weak randomness. The concise-info agent cut the analyzed context by about 86% (23.6K of 166K estimated tokens). I spot-checked the findings but did not label them all, so I don't report precision on WebGoat.

## Tests and CI

```bash
python -m pytest -q
```

The tests cover each agent: partitioning, condensing, validator rejection of fabricated findings, the garbage-collector memory bound on a large generated project, fix validation, the Bedrock provider (using a fake client), the CLI, and the Lambda handler. GitHub Actions runs the tests and benchmark, then compiles the original samples and the patched output with `javac` (JDK 21) to confirm the fixes are valid Java.

## Limitations

- Detection is pattern- and context-based within a method. There is no inter-procedural taint tracking, so a tainted value passed through helper methods can be missed.
- The Bedrock path is unit-tested with a stubbed client only. Real model output varies, and the Validator is what keeps it honest.
- Autofixes are intentionally conservative. Rules that need structural rewrites (e.g. `PreparedStatement`) get guidance instead of an edit.

## Layout

```
vulnagents/
  agents/        partitioner, condenser (concise-info), scanner, validator, remediator, gc
  rules.py       rule definitions and autofixes
  providers.py   RuleProvider, BedrockProvider, JSON parsing
  memory.py      shared memory with token budget
  orchestrator.py, cli.py, report.py, benchmark.py
lambda_handler.py
samples/         vulnerable/ and safe/ Java sources
tests/
```
