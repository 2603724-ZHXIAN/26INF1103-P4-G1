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
        """Display potential scam campaigns in a compact table."""

        document.add_heading("Potential Scam Campaigns", level=1)

        campaign_groups = [
            group
            for group in report.get_campaign_groups()
            if group["count"] >= 2
        ]

        if not campaign_groups:
            document.add_paragraph("No campaign groups available.")
            return

        table = document.add_table(rows=1, cols=4)
        table.style = "Table Grid"

        headers = [
            "Campaign",
            "Emails",
            "Submission IDs",
            "Common Threat",
        ]

        for index, heading in enumerate(headers):
            table.rows[0].cells[index].text = heading

        for index, group in enumerate(campaign_groups, start=1):
            cells = table.add_row().cells

            cells[0].text = f"Group {index}"
            cells[1].text = str(group["count"])

            submission_ids = group["submission_ids"]
            visible_ids = submission_ids[:3]
            remaining = len(submission_ids) - len(visible_ids)

            id_text = ", ".join(str(item) for item in visible_ids)

            if remaining > 0:
                id_text += f" +{remaining} more"

            cells[2].text = id_text

            patterns = report.get_campaign_patterns(group)
            common_threats = patterns["common_threat_types"]

            if common_threats:
                cells[3].text = ", ".join(
                    str(threat["threat_type"]).title()
                    for threat in common_threats
                )
            else:
                cells[3].text = "Unknown"

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
        """Group AI educational guidance by threat type."""

        document.add_heading("AI Educational Guidance", level=1)

        grouped_guidance = {}

        for record in report.email_records:
            if record.get("processing_status") != "completed":
                continue

            threat_summary = record.get("threat_summary")
            preventive_steps = record.get("preventive_steps") or []
            recovery_steps = record.get("recovery_steps") or []

            if not threat_summary and not preventive_steps and not recovery_steps:
                continue

            threat_type = record.get("primary_threat_type") or "Unknown"
            threat_type = str(threat_type).strip().lower() or "unknown"

            if threat_type not in grouped_guidance:
                grouped_guidance[threat_type] = {
                    "submission_ids": [],
                    "summaries": [],
                    "preventive_steps": [],
                    "recovery_steps": [],
                }

            group = grouped_guidance[threat_type]
            group["submission_ids"].append(record.get("submission_id"))

            if threat_summary and threat_summary not in group["summaries"]:
                group["summaries"].append(threat_summary)

            for field, steps in (
                ("preventive_steps", preventive_steps),
                ("recovery_steps", recovery_steps),
            ):
                if not isinstance(steps, list):
                    continue

                for step in steps:
                    step_text = str(step).strip()

                    if step_text and step_text not in group[field]:
                        group[field].append(step_text)

        if not grouped_guidance:
            document.add_paragraph("No educational guidance available.")
            return

        for threat_type, group in grouped_guidance.items():
            count = len(group["submission_ids"])

            document.add_heading(
                f"{threat_type.title()} — {count} emails",
                level=2,
            )

            ids = group["submission_ids"]
            visible_ids = ids[:5]
            remaining = len(ids) - len(visible_ids)

            id_text = ", ".join(str(item) for item in visible_ids)

            if remaining > 0:
                id_text += f" +{remaining} more"

            document.add_paragraph(f"Submissions: {id_text}")

            sections = [
                ("Threat Summaries", group["summaries"]),
                ("Preventive Steps", group["preventive_steps"]),
                ("Recovery Steps", group["recovery_steps"]),
            ]

            for heading, items in sections:
                if not items:
                    continue

                document.add_paragraph(heading + ":")

                for item in items:
                    document.add_paragraph(
                        str(item),
                        style="List Bullet",
                    )

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