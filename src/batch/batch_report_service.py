
from src.batch.batch_report import BatchReport


class BatchReportService:
    """Build batch reports using records saved in the database."""

    def __init__(self, data_manager) -> None:
        self._data_manager = data_manager

    def build_report(self, batch_reference: str) -> BatchReport:
        """Retrieve saved batch data and construct a BatchReport."""

        batches = self._data_manager.list_email_batches()

        batch_info = next(
            (
                batch
                for batch in batches
                if batch["batch_reference"] == batch_reference
            ),
            None,
        )

        if batch_info is None:
            raise ValueError("No batch exists with that reference.")

        submissions = self._data_manager.get_batch_submissions(
            batch_reference
        )

        email_records = []

        for submission in submissions:
            detailed_report = self._data_manager.get_submission_report(
                submission["submission_id"]
            )

            if detailed_report is None:
                email_records.append(submission.copy())
            else:
                email_records.append({
                    **submission,
                    **detailed_report,
                })

        return BatchReport(batch_info, email_records)
