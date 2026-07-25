import logging

from .action import Action

WARNING: int = 2
SUCCESS: int = 1
ERROR: int = 0


class ActionResult:
    __slots__ = ['action', 'statuses', 'reasons']

    def __init__(self, action: Action) -> None:
        self.action: Action = action
        self.statuses: list[int] = []
        self.reasons: list[str | None] = []

    def add_result(self, status: int, reason: str | None = None) -> None:
        self.statuses.append(status)
        self.reasons.append(reason)

    def passed(self) -> bool:
        return len(self.statuses) == 0 or not any([x == ERROR for x in self.statuses])

    def print(self, level: int) -> None:
        for i, status in enumerate(self.statuses):
            reason_str = f"[{self.action.display_name()}] {self.reasons[i]}" if self.reasons[i] else \
                f"[{self.action.display_name()}] " + ("Passed" if status else "Failed") + " (No Message)."
            if status > level:
                continue

            if status == WARNING:
                logging.warning(reason_str)
            elif status == SUCCESS:
                logging.success(reason_str)
            elif status == ERROR:
                logging.error(reason_str)

    def format_lines(self, level: int) -> list[str]:
        labels = {WARNING: "WARNING", SUCCESS: "SUCCESS", ERROR: "ERROR"}
        lines = []
        for i, status in enumerate(self.statuses):
            if status > level:
                continue
            msg = f"[{self.action.display_name()}] {self.reasons[i]}" if self.reasons[i] else \
                f"[{self.action.display_name()}] " + ("Passed" if status else "Failed") + " (No Message)."
            lines.append(f"{labels[status]}: {msg}")
        return lines
