"""Scanner agent: asks a provider (rules or an LLM) for candidate findings in a condensed context."""


class ScannerAgent:
    name = "scanner"

    def __init__(self, provider):
        self.provider = provider

    def scan(self, context, notes: str = ""):
        if not context.lines:
            return []
        return self.provider.analyze(context, notes)
