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

    def generate_summary(self) -> dict:
        """Return saved processing and risk statistics for this batch."""

        return {
            "batch_reference": self._batch_info.get("batch_reference"),
            "total_emails": self._batch_info.get("saved_email_count") or 0,
            "completed": self._batch_info.get("completed_count") or 0,
            "failed": self._batch_info.get("analysis_failed_count") or 0,
            "high_risk": self._batch_info.get("high_risk_count") or 0,
            "medium_risk": self._batch_info.get("medium_risk_count") or 0,
            "low_risk": self._batch_info.get("low_risk_count") or 0,
        }