from vulnagents.agents.condenser import ConciseInfoAgent
from vulnagents.agents.gc import GarbageCollectorAgent
from vulnagents.agents.partitioner import PartitionerAgent
from vulnagents.agents.validator import ValidatorAgent
from vulnagents.memory import Entry, SharedMemory
from vulnagents.orchestrator import Orchestrator

SOURCE = """package demo;

public class Demo {
    private int count = 0;

    public String hello(String name) {
        return "hi " + name;
    }

    public void run(String cmd) throws Exception {
        int a = 1;
        int b = 2;
        Runtime.getRuntime().exec("sh -c " + cmd);
        int c = a + b;
    }
}
"""


def chunk_named(name):
    return next(c for c in PartitionerAgent().partition_source(SOURCE, "Demo.java") if c.name == name)


class TestPartitioner:
    def test_splits_into_methods_and_class_level_code(self):
        chunks = PartitionerAgent().partition_source(SOURCE, "Demo.java")
        names = [c.name for c in chunks]
        assert "hello" in names and "run" in names and "<class-level>" in names
        run = chunk_named("run")
        assert (run.start_line, run.end_line) == (10, 15)

    def test_bounds_large_methods(self):
        body = "\n".join(f"        int v{i} = {i};" for i in range(130))
        source = f"public class Big {{\n    void big() {{\n{body}\n    }}\n}}\n"
        chunks = [c for c in PartitionerAgent(max_lines=50).partition_source(source, "Big.java") if c.name.startswith("big")]
        assert len(chunks) == 3
        assert all(len(c.lines) <= 50 for c in chunks)


class TestConciseInfo:
    def test_keeps_signal_lines_with_neighbors_and_signature(self):
        context = ConciseInfoAgent().condense(chunk_named("run"))
        assert sorted(context.lines) == [10, 12, 13, 14]
        assert context.tokens_after < context.tokens_before

    def test_skips_chunks_without_signals(self):
        assert ConciseInfoAgent().condense(chunk_named("hello")).lines == {}


class TestValidator:
    def test_accepts_supported_finding(self):
        accepted, rejected = ValidatorAgent().validate_findings(
            [{"rule_id": "CMDI", "line": 13, "evidence": 'Runtime.getRuntime().exec("sh -c " + cmd);'}],
            chunk_named("run"),
        )
        assert len(accepted) == 1 and rejected == []
        assert accepted[0].cwe == "CWE-78"

    def test_rejects_hallucinated_findings(self):
        chunk = chunk_named("run")
        raw = [
            {"rule_id": "SQLI", "line": 13, "evidence": "stmt.executeQuery(sql)"},  # evidence not on that line
            {"rule_id": "CMDI", "line": 99, "evidence": "exec"},  # outside the chunk
            {"rule_id": "BUFFER_OVERFLOW", "line": 13},  # unknown rule
            {"rule_id": "CMDI", "line": "thirteen"},  # bad line number
        ]
        accepted, rejected = ValidatorAgent().validate_findings(raw, chunk)
        assert accepted == []
        reasons = [r.reason for r in rejected]
        assert "evidence does not appear on line 13" in reasons
        assert any("outside the analyzed chunk" in r for r in reasons)
        assert any("unknown rule" in r for r in reasons)
        assert "missing or invalid line number" in reasons

    def test_rejects_duplicates(self):
        validator = ValidatorAgent()
        finding = {"rule_id": "CMDI", "line": 13}
        validator.validate_findings([finding], chunk_named("run"))
        accepted, rejected = validator.validate_findings([finding], chunk_named("run"))
        assert accepted == [] and rejected[0].reason == "duplicate"


class TestGarbageCollector:
    def test_evicts_context_after_each_task(self):
        memory = SharedMemory(budget_tokens=1000)
        memory.put(Entry(key="context:A.java:1-10", kind="context", text="x" * 400, file="A.java"))
        GarbageCollectorAgent().collect(memory, "A.java:1-10")
        assert memory.of_kind("context") == []
        assert memory.evicted_tokens == 100

    def test_summarizes_findings_when_over_budget(self):
        memory = SharedMemory(budget_tokens=10)
        for line in range(1, 8):
            memory.put(Entry(key=f"finding:A.java:{line}:SQLI", kind="finding", text=f"SQLI line {line}", file="A.java"))
        memory.put(Entry(key="finding:A.java:9:WEAK_HASH", kind="finding", text="WEAK_HASH line 9", file="A.java"))
        GarbageCollectorAgent().collect(memory, "none")
        assert memory.of_kind("finding") == []
        assert memory.notes_for("A.java") == "A.java: SQLIx7, WEAK_HASHx1"
        assert memory.total_tokens <= 10

    def test_memory_stays_within_budget_on_a_large_project(self):
        method = '    void m{i}(String id) throws Exception {{ stmt.executeQuery("SELECT * FROM t WHERE id = " + id); }}\n'
        sources = {
            f"F{f}.java": "public class F%d {\n" % f + "".join(method.format(i=i) for i in range(20)) + "}\n"
            for f in range(15)
        }
        report = Orchestrator(memory_budget_tokens=200).scan_sources(sources)
        assert len(report.findings) == 300
        assert report.metrics["peak_memory_tokens"] <= 200 + 60  # one task's context can briefly exceed the budget
