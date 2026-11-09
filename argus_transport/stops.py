class TargetRunStopped(Exception):
    def __init__(self, reason: str, detail: str = ''):
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail
        self.checklist: tuple[str, ...] = ()
        self.cleanup: dict | None = None
        self.target_cleanup: dict | None = None
        self.transport_diagnostics: dict = {}

    def set_cleanup(self, report: dict | None) -> None:
        if report is not None:
            if self.cleanup is None:
                self.cleanup = report
            else:
                self.cleanup.clear()
                self.cleanup.update(report)
            self.target_cleanup = self.cleanup
            self.transport_diagnostics['cleanup'] = self.cleanup



RunStopped = TargetRunStopped
