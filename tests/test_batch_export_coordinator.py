
import unittest
from unittest.mock import Mock, patch

from src.coordinator import EngineCoordinator
from pathlib import Path

class TestBatchExportCoordinator(unittest.TestCase):

    @patch("src.coordinator.Path.exists", return_value=False)
    @patch("src.coordinator.WordReportWriter")
    @patch("src.coordinator.BatchReportService")
    def test_option_four_exports_word_report(
        self, mock_report_service, mock_writer, mock_exists
    ):
        io_manager = Mock()
        ai_manager = Mock()
        logic_manager = Mock()
        data_manager = Mock()

        coordinator = EngineCoordinator(
            io_manager,
            ai_manager,
            logic_manager,
            data_manager,
        )

        batch = {"batch_reference": "BATCH-001"}

        data_manager.search_batch_emails.return_value = []

        data_manager.list_email_batches.return_value = [
            {
                "batch_id": 1,
                "batch_reference": "BATCH-001",
            }
        ]

        io_manager.collect_batch_review_request.side_effect = [
            {"choice": "4"},
            {"choice": "0"},
        ]

        fake_report = Mock()
        mock_report_service.return_value.build_report.return_value = (
            fake_report
        )

        mock_writer.return_value.export.return_value = (
            "reports/BATCH-0001.docx"
        )

        coordinator._review_email_batch(batch)

        mock_report_service.assert_called_once_with(data_manager)

        mock_report_service.return_value.build_report.assert_called_once_with(
            "BATCH-001"
        )

        mock_writer.return_value.export.assert_called_once_with(
            fake_report,
            str(Path("reports") / "BATCH-0001.docx"),
        )

        io_manager._print.assert_called_with(
            "Word report saved successfully: reports/BATCH-0001.docx"
        )


    @patch("src.coordinator.WordReportWriter")
    @patch("src.coordinator.BatchReportService")
    def test_option_four_handles_export_failure(
        self, mock_report_service, mock_writer
    ):
        io_manager = Mock()
        ai_manager = Mock()
        logic_manager = Mock()
        data_manager = Mock()

        coordinator = EngineCoordinator(
            io_manager,
            ai_manager,
            logic_manager,
            data_manager,
        )

        batch = {"batch_reference": "BATCH-001"}

        data_manager.search_batch_emails.return_value = []

        data_manager.list_email_batches.return_value = [
            {
                "batch_id": 1,
                "batch_reference": "BATCH-001",
            }
        ]

        io_manager.collect_batch_review_request.side_effect = [
            {"choice": "4"},
            {"choice": "0"},
        ]

        mock_report_service.return_value.build_report.return_value = Mock()

        mock_writer.return_value.export.side_effect = OSError(
            "Permission denied"
        )

        coordinator._review_email_batch(batch)

        mock_writer.return_value.export.assert_called_once()

        io_manager._print.assert_any_call(
            "Could not export Word report: Permission denied"
        )


if __name__ == "__main__":
    unittest.main()
