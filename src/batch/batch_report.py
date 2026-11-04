class BatchReport:
    """Prepare statistics and rankings for an analysed email batch."""

    def __init__(self, batch_info: dict, email_records: list[dict]) -> None:
        self._batch_info = batch_info.copy()
        self._email_records = [record.copy() for record in email_records]

    @property
    def batch_info(self) -> dict:
        return self._batch_info.copy()

    @property
    def email_records(self) -> list[dict]:
        return [record.copy() for record in self._email_records]