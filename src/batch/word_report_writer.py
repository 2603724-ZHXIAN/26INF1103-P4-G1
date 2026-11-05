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

        self._add_executive_summary(document, summary)
        self._add_summary_section(document, summary)

       
        # Risk Distribution
        self._add_risk_section(document, report, summary)

        # Top Threat Types
        self._add_threat_section(document, report)

        # Ranked Email Results
        self._add_ranked_section(document, report)

        self._add_all_emails_section(document, report)

        # Campaign Grouping
        self._add_campaign_section(document, report)

        # Failed Email Details
        self._add_failed_section(document, report)

        # AI Educational Guidance
        self._add_guidance_section(document, report)

        # Methodology and Limitations
        self._add_methodology_section(document)

        destination = Path(output_path)

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

        campaign_groups = [
            group
            for group in report.get_campaign_groups()
            if group["count"] >= 2
        ]

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
        """Display detailed high-risk email findings."""

        document.add_heading("Prioritised High-Risk Emails", level=1)

        ranked_results = report.get_high_risk_results()
        total_high_risk = len(ranked_results)
        ranked_results = ranked_results[:10]
        remaining_count = total_high_risk - len(ranked_results)

        if not ranked_results:
            document.add_paragraph("No high-risk emails identified.")
            return

        for result in ranked_results:
            submission_id = result.get("submission_id")
            risk_level = result.get("overall_risk") or "Unknown"
            risk_score = result.get("risk_score")
            threat_type = result.get("primary_threat_type")
            threat_summary = result.get("threat_summary")
            recommended_action = result.get("recommended_action")
            risk_reasons = result.get("risk_reasons") or []

            document.add_heading(
                f"Submission #{submission_id}",
                level=2
            )

            document.add_paragraph(
                f"Risk Level: {str(risk_level).title()}"
            )

            document.add_paragraph(
                f"Risk Score: {risk_score}/100"
            )

            if threat_type:
                document.add_paragraph(
                    f"Threat Type: {str(threat_type).title()}"
                )

            if threat_summary:
                document.add_paragraph(
                    f"Threat Summary: {threat_summary}"
                )

            if isinstance(risk_reasons, list) and risk_reasons:
                document.add_paragraph("Why This Email Is Risky:")

                for reason in risk_reasons:
                    document.add_paragraph(
                        str(reason),
                        style="List Bullet"
                    )

            if recommended_action:
                document.add_paragraph(
                    f"Recommended Action: {recommended_action}"
                )

        if remaining_count > 0:
            document.add_paragraph(
                f"Plus {remaining_count} more high-risk emails. "
                "See the All-Email Summary table for their details."
            )

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

    def _add_guidance_section(
        self, document, report: BatchReport
    ) -> None:
        """Add AI-generated educational guidance to the Word document."""

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
                    document.add_paragraph(
                        str(step),
                        style="List Bullet"
                    )

            if isinstance(recovery_steps, list) and recovery_steps:
                document.add_paragraph("Recovery Steps:")

                for step in recovery_steps:
                    document.add_paragraph(
                        str(step),
                        style="List Bullet"
                    )

        if not guidance_found:
            document.add_paragraph("No educational guidance available.")

    def _add_methodology_section(self, document) -> None:
        """Explain the report methodology and its limitations."""

        document.add_heading("Methodology and Limitations", level=1)

        document.add_heading("Methodology", level=2)

        methodology = [
            "Emails are analysed using AI and predefined business rules.",
            "Risk distribution is calculated from classified emails.",
            "Common threat types are counted from completed analyses.",
            "High-risk emails are prioritised by risk score.",
            "Similar emails are grouped using text similarity."
        ]

        for item in methodology:
            document.add_paragraph(item, style="List Bullet")

        document.add_heading("Limitations", level=2)

        limitations = [
            "AI-generated classifications may be inaccurate.",
            "Similar emails do not necessarily originate from the same attacker.",
            "Failed analyses are excluded from risk classifications.",
            "Risk scores indicate potential threats but are not guarantees."
        ]

        for item in limitations:
            document.add_paragraph(item, style="List Bullet")

    def _add_executive_summary(
        self, document, summary: dict
    ) -> None:
        """Add a concise overview of the batch findings."""

        total = summary["total_emails"]
        completed = summary["completed"]
        failed = summary["failed"]
        high_risk = summary["high_risk"]

        document.add_heading("Executive Summary", level=1)

        if total == 0:
            message = "No emails were submitted for analysis."

        elif completed == 0 and failed > 0:
            message = (
                f"{total} emails were submitted, but none were "
                f"successfully analysed. {failed} analyses failed. "
                "The batch results are incomplete and require attention."
            )

        else:
            message = (
                f"{total} emails submitted: {completed} successfully "
                f"analysed, {failed} failed. "
                f"{high_risk} high-risk emails require attention."
            )

        document.add_paragraph(message)

    def _add_all_emails_section(
        self, document, report: BatchReport
    ) -> None:
        """Display all batch emails in a compact summary table."""

        document.add_heading("All-Email Summary", level=1)

        ranked_results = report.get_ranked_results()
        ranked_ids = {
            result.get("submission_id")
            for result in ranked_results
        }

        remaining_records = [
            record
            for record in report.email_records
            if record.get("submission_id") not in ranked_ids
        ]

        all_records = ranked_results + remaining_records

        if not all_records:
            document.add_paragraph("No emails available.")
            return

        table = document.add_table(rows=1, cols=4)
        table.style = "Table Grid"

        headers = [
            "Email ID",
            "Risk Level",
            "Score",
            "Threat Type",
        ]

        for index, heading in enumerate(headers):
            table.rows[0].cells[index].text = heading

        for record in all_records:
            row = table.add_row().cells

            status = record.get("processing_status")
            risk = record.get("overall_risk")
            score = record.get("risk_score")
            threat = record.get("primary_threat_type")

            row[0].text = str(record.get("submission_id", "—"))

            if status == "failed":
                row[1].text = "Failed"
                row[2].text = "—"
                row[3].text = "—"
            else:
                row[1].text = str(risk).title() if risk else "Unknown"
                row[2].text = str(score) if score is not None else "—"
                row[3].text = str(threat).title() if threat else "—"