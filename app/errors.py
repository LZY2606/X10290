class ProtocolError(Exception):
    kind = "semantic_unresolvable"

    def __init__(self, message, path=None, candidates=None):
        super().__init__(message)
        self.path = path or "$"
        self.candidates = candidates or []

    def to_dict(self):
        result = {"kind": self.kind, "message": str(self), "path": self.path}
        if self.candidates:
            result["candidates"] = self.candidates
        return result


class MalformedInput(ProtocolError):
    kind = "format_corrupt"


class BudgetExhausted(ProtocolError):
    kind = "budget_exhausted"


class IncompleteInput(ProtocolError):
    kind = "incomplete_input"

