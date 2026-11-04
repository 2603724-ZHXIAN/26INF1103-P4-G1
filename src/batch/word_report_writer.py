from pathlib import Path
from docx import Document

from src.batch.batch_report import BatchReport


class WordReportWriter:
    """Export batch analysis results to a Word document."""

    def export(self, report: BatchReport, output_path: str) -> str:
        """Create and save a Word report."""

        document = Document()

        document.add_heading(
            "Cyber Threat & Scam Detection - Batch Report",
            level=0
        )

        summary = report.generate_summary()
        self._add_summary_section(document, summary)

       
        # Risk Distribution
        self._add_risk_section(document, report, summary)

        # Top Threat Types
        self._add_threat_section(document, report)

        # Ranked Email Results
        self._add_ranked_section(document, report)

        # Campaign Grouping
        self._add_campaign_section(document, report)

        # Failed Email Details
        self._add_failed_section(document, report)

        # AI Educational Guidance
        document.add_heading("AI Educational Guidance", level=1)

        guidance_found = False

        for record in report.email_records:
            if record.get("processing_status") != "completed":
                continue

            threat_summary = record.get("threat_summary")
            preventive_steps = record.get("preventive_steps") or []
            recovery_steps = record.get("recovery_steps") or []

            if not threat_summary and not preventive_steps and not recovery_steps:
                continue

            guidance_found = True

            document.add_heading(
                f"Submission {record.get('submission_id')}",
                level=2
            )

            if threat_summary:
                document.add_paragraph(
                    f"Threat Summary: {threat_summary}"
                )

            if isinstance(preventive_steps, list) and preventive_steps:
                document.add_paragraph("Preventive Steps:")

                for step in preventive_steps:
                    document.add_paragraph(str(step), style="List Bullet")

            if isinstance(recovery_steps, list) and recovery_steps:
                document.add_paragraph("Recovery Steps:")

                for step in recovery_steps:
                    document.add_paragraph(str(step), style="List Bullet")

        if not guidance_found:
            document.add_paragraph("No educational guidance available.")

        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        document.save(destination)

        return str(destination)

    def _add_summary_section(self, document, summary: dict) -> None:
        """Add batch summary information to the Word document."""

        document.add_heading("Batch Summary", level=1)

        document.add_paragraph(
            f"Batch Reference: {summary['batch_reference']}"
        )
        document.add_paragraph(
            f"Total Emails: {summary['total_emails']}"
        )
        document.add_paragraph(
            f"Completed: {summary['completed']}"
        )
        document.add_paragraph(
            f"Failed: {summary['failed']}"
        )

    def _add_risk_section(
        self, document, report: BatchReport, summary: dict
    ) -> None:
        """Add risk counts and percentages to the Word document."""

        document.add_heading("Risk Distribution", level=1)

        risk_distribution = report.get_risk_distribution()

        table = document.add_table(rows=1, cols=3)
        table.style = "Table Grid"

        header = table.rows[0].cells
        header[0].text = "Risk Level"
        header[1].text = "Email Count"
        header[2].text = "Percentage"

        risk_levels = [
            ("High", summary["high_risk"], risk_distribution["high"]),
            ("Medium", summary["medium_risk"], risk_distribution["medium"]),
            ("Low", summary["low_risk"], risk_distribution["low"])
        ]

        for level, count, percentage in risk_levels:
            cells = table.add_row().cells
            cells[0].text = level
            cells[1].text = str(count)
            cells[2].text = f"{percentage:.2f}%"

    def _add_threat_section(
        self, document, report: BatchReport
    ) -> None:
        """Add the most common threat types to the Word document."""

        document.add_heading("Top Threat Types", level=1)

        common_threats = report.get_common_threats()

        if common_threats:
            threat_table = document.add_table(rows=1, cols=2)
            threat_table.style = "Table Grid"

            header = threat_table.rows[0].cells
            header[0].text = "Threat Type"
            header[1].text = "Email Count"

            for threat in common_threats:
                cells = threat_table.add_row().cells
                cells[0].text = threat["threat_type"].title()
                cells[1].text = str(threat["count"])
        else:
            document.add_paragraph("No classified threats available.")

    def _add_campaign_section(
        self, document, report: BatchReport
    ) -> None:
        """Add similar email groups to the Word document."""

        document.add_heading("Potential Scam Campaigns", level=1)

        campaign_groups = report.get_campaign_groups()

        if campaign_groups:
            for index, group in enumerate(campaign_groups, start=1):
                document.add_heading(f"Campaign Group {index}", level=2)

                document.add_paragraph(
                    f"Number of Emails: {group['count']}"
                )

                document.add_paragraph(
                    "Submission IDs: "
                    + ", ".join(str(id) for id in group["submission_ids"])
                )

                patterns = report.get_campaign_patterns(group)

                if patterns["common_threat_types"]:
                    document.add_paragraph("Common Threat Types:")

                    for threat in patterns["common_threat_types"]:
                        document.add_paragraph(
                            f"{threat['threat_type'].title()}: {threat['count']}",
                            style="List Bullet"
                        )
                else:
                    document.add_paragraph("No common threat types identified.")
        else:
            document.add_paragraph("No campaign groups available.")

    def _add_ranked_section(
        self, document, report: BatchReport
    ) -> None:
        """Add ranked email results to the Word document."""

        document.add_heading("Ranked Email Results", level=1)

        ranked_results = report.get_ranked_results()

        if ranked_results:
            ranked_table = document.add_table(rows=1, cols=3)
            ranked_table.style = "Table Grid"

            header = ranked_table.rows[0].cells
            header[0].text = "Submission ID"
            header[1].text = "Risk Level"
            header[2].text = "Risk Score"

            for result in ranked_results:
                cells = ranked_table.add_row().cells
                cells[0].text = str(result["submission_id"])
                cells[1].text = str(result["overall_risk"]).title()
                cells[2].text = str(result["risk_score"])
        else:
            document.add_paragraph("No ranked email results available.")

    def _add_failed_section(
        self, document, report: BatchReport
    ) -> None:
        """Add failed email analyses to the Word document."""

        document.add_heading("Failed Email Analyses", level=1)

        failed_records = [
            record
            for record in report.email_records
            if record.get("processing_status") == "failed"
        ]

        if failed_records:
            failed_table = document.add_table(rows=1, cols=2)
            failed_table.style = "Table Grid"

            header = failed_table.rows[0].cells
            header[0].text = "Submission ID"
            header[1].text = "Error Message"

            for record in failed_records:
                cells = failed_table.add_row().cells
                cells[0].text = str(record.get("submission_id") or "Unknown")
                cells[1].text = str(
                    record.get("error_message") or "No error details available"
                )
        else:
            document.add_paragraph("No failed email analyses.")