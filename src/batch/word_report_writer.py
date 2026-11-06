from pathlib import Path
from unittest import result
from docx import Document

from src.batch.batch_report import BatchReport
from docx.shared import RGBColor
from docx.shared import RGBColor, Pt
from docx.oxml import OxmlElement
from docx.oxml.ns import qn


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
        self._add_import_summary(document, summary)
        self._add_import_issues_section(document, report)

       
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

    def _add_import_summary(self, document, summary: dict) -> None:
        """Display the batch's saved email import statistics."""

        document.add_heading("Batch Import Summary", level=1)

        table = document.add_table(rows=1, cols=2)
        table.style = "Table Grid"

        header = table.rows[0].cells
        header[0].text = "Import Status"
        header[1].text = "Count"

        import_statistics = [
            ("Uploaded Files", summary["uploaded_files"]),
            ("Accepted Emails", summary["accepted_emails"]),
            ("Duplicate Files", summary["duplicate_files"]),
            ("Failed Imports", summary["failed_imports"]),
        ]

        for status, count in import_statistics:
            cells = table.add_row().cells
            cells[0].text = status
            cells[1].text = str(count)

        self._style_table(table)

    def _add_import_issues_section(self, document, report: BatchReport) -> None:
        """Display duplicate files and failed imports saved for this batch."""

        document.add_heading(
            "Emails Not Scanned — Duplicates and Failed Imports",
            level=1
        )

        issues = report.import_issues

        if not issues:
            document.add_paragraph(
                "No duplicate files or failed imports were recorded."
            )
            return

        table = document.add_table(rows=1, cols=4)
        table.style = "Table Grid"

        headers = table.rows[0].cells
        headers[0].text = "Email Reference"
        headers[1].text = "Filename"
        headers[2].text = "Status"
        headers[3].text = "Reason"

        for issue in issues:
            cells = table.add_row().cells

            cells[0].text = str(issue.get("item_id") or "N/A")
            cells[1].text = str(issue.get("source_path") or "Unknown")
            cells[2].text = str(issue.get("kind") or "Unknown")
            cells[3].text = str(issue.get("message") or "Not provided")

        self._style_table(table)



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

        self._style_table(table)
        

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

            self._style_table(threat_table)
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
            "Email IDs",
            "Common Threat",
        ]

        for index, heading in enumerate(headers):
            table.rows[0].cells[index].text = heading

        for index, group in enumerate(campaign_groups, start=1):
            cells = table.add_row().cells

            cells[0].text = f"Group {index}"
            cells[1].text = str(group["count"])

            # Map internal submission IDs to user-facing Email IDs.
            email_id_lookup = {
                record["submission_id"]: record.get("email_id") or "Unavailable"
                for record in report.email_records
                if record.get("submission_id") is not None
            }

            submission_ids = group["submission_ids"]

            email_ids = [
                email_id_lookup.get(submission_id, "Unavailable")
                for submission_id in submission_ids
            ]

            visible_ids = email_ids[:3]
            remaining = len(email_ids) - len(visible_ids)

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

        self._style_table(table)

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
            email_id = result.get("email_id") or "Unavailable"
            risk_level = result.get("overall_risk") or "Unknown"
            threat_type = result.get("primary_threat_type")
            threat_summary = result.get("threat_summary")
            recommended_action = result.get("recommended_action")
            risk_reasons = result.get("risk_reasons") or []

            document.add_heading(
                f"Email ID: {email_id}",
                level=2
            )

            document.add_paragraph(
                f"Risk Level: {str(risk_level).title()}"
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
            header[0].text = "Email ID"
            header[1].text = "Error Message"

            for record in failed_records:
                cells = failed_table.add_row().cells
                cells[0].text = str(record.get("email_id") or "Unavailable")
                cells[1].text = str(
                    record.get("error_message") or "No error details available"
                )

            self._style_table(failed_table)

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
            group["submission_ids"].append(
                record.get("email_id") or "Unavailable"
            )

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

            document.add_paragraph(f"Email IDs: {id_text}")

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
            "Emails are prioritised by risk category (High, Medium, Low).",
            "Similar emails are grouped using text similarity."
        ]

        for item in methodology:
            document.add_paragraph(item, style="List Bullet")

        document.add_heading("Limitations", level=2)

        limitations = [
            "AI-generated classifications may be inaccurate.",
            "Similar emails do not necessarily originate from the same attacker.",
            "Failed analyses are excluded from risk classifications.",
            "Risk categories indicate potential threats but are not guarantees."
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

    def _apply_risk_colour(self, cell, risk_level: str) -> None:
        """Apply a consistent colour to a risk-level table cell."""

        colours = {
            "high": RGBColor(192, 0, 0),
            "medium": RGBColor(191, 143, 0),
            "low": RGBColor(0, 128, 0),
            "failed": RGBColor(100, 100, 100),
        }

        colour = colours.get(str(risk_level).lower())

        if colour is None:
            return

        for paragraph in cell.paragraphs:
            for run in paragraph.runs:
                run.font.color.rgb = colour
                run.bold = True


    def _style_table(self, table) -> None:
        """Apply consistent formatting to a Word table."""

        table.style = "Table Grid"

        for row_index, row in enumerate(table.rows):
            for cell in row.cells:

                # Shade the header row.
                if row_index == 0:
                    shading = OxmlElement("w:shd")
                    shading.set(qn("w:fill"), "DCE6F1")
                    cell._tc.get_or_add_tcPr().append(shading)

                # Format the text inside each cell.
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.font.size = Pt(9)

                        if row_index == 0:
                            run.bold = True



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

        # Three columns: numerical scores are not used.
        table = document.add_table(rows=1, cols=3)
        table.style = "Table Grid"

        headers = [
            "Email ID",
            "Risk Level",
            "Threat Type",
        ]

        for index, heading in enumerate(headers):
            table.rows[0].cells[index].text = heading

        for record in all_records:
            row = table.add_row().cells

            status = record.get("processing_status")
            risk = record.get("overall_risk")
            threat = record.get("primary_threat_type")

            row[0].text = str(record.get("email_id") or "Unavailable")

            if status == "failed":
                row[1].text = "Failed"
                row[2].text = "—"
            else:
                row[1].text = str(risk).title() if risk else "Unknown"
                row[2].text = str(threat).title() if threat else "—"

            self._apply_risk_colour(row[1], row[1].text)

        self._style_table(table)
