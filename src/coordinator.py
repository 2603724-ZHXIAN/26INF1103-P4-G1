"""EngineCoordinator: Central orchestrator for the Cyber Threat Detection Engine.

Demonstrates OOP Rubric Principles:
- Composition:   Owns the lifecycle of IOManager, AIManager, LogicManager, DataManager.
- Aggregation:   Receives VirusTotalScanner via dependency injection (concrete service, YAGNI applied).
- Association:   Coordinates managers by dynamically passing domain entities (Submission,
                 AssessmentResult) through method calls ("Uses-A" relationship).
- Encapsulation: All manager references are private (_io, _ai, _logic, _data, _scanner).
- SRP:           Only responsibility is routing and orchestrating the four managers;
                 zero business-logic, zero SQL, zero UI formatting lives here.
- OCP:           New pipelines are added as new _handle_* methods without touching run().
"""

import json
import logging
from typing import Optional

from .managers.ai_manager import AIManager
from .managers.data_manager import DataManager, DataManagerError
from .managers.io_manager import IOManager
from .managers.logic_manager import LogicManager
from .models.submission import Submission
from .services.virustotal_scanner import VirusTotalScanner
from .services.email_ingestion_service import EmailIngestionService

LOGGER = logging.getLogger(__name__)


class EngineCoordinator:
    """Top-level orchestrator that wires all four managers into a coherent engine loop.

    Demonstrates:
    - Composition:  Owns IOManager, AIManager, LogicManager, DataManager.
    - Aggregation:  Holds VirusTotalScanner injected from outside (scanner's lifecycle
                    is managed by the caller, not this coordinator; YAGNI applied).
    - Association:  Passes Submission and AssessmentResult objects dynamically across
                    pipeline steps ("Uses-A").
    - Encapsulation: All dependencies are private attributes; no public setters expose
                     internal wiring.
    - SRP:           Solely responsible for routing user requests to the correct pipeline
                     and persisting results; each pipeline step is a private method.
    - OCP:           New action types are added by implementing a new _handle_* method;
                     the run() loop requires no modification.
    """

    def __init__(
        self,
        io_manager: IOManager,
        ai_manager: AIManager,
        logic_manager: LogicManager,
        data_manager: DataManager,
        scanner: Optional[VirusTotalScanner] = None,
        ingestion_service: Optional[EmailIngestionService] = None,
    ) -> None:
        """Initialise the coordinator with its composed and aggregated dependencies.

        Args:
            io_manager:    Presentation layer (Composition — coordinator owns its use).
            ai_manager:    LLM orchestration layer (Composition).
            logic_manager: Business rule engine (Composition).
            data_manager:  Persistence layer (Composition).
            scanner:       VirusTotalScanner service (Aggregation — injected, not owned).
        """
        # Composition: all four managers are created outside and composed here
        self._io: IOManager = io_manager
        self._ai: AIManager = ai_manager
        self._logic: LogicManager = logic_manager
        self._data: DataManager = data_manager

        # Aggregation: VirusTotalScanner is injected (standalone concrete service)
        self._scanner: Optional[VirusTotalScanner] = scanner
        self._ingestion = ingestion_service

    # -------------------------------------------------------------------------
    # Public Entry Point
    # -------------------------------------------------------------------------

    def run(self) -> None:
        """Main event loop: display menu, dispatch actions, repeat until exit.

        OCP: Dispatching is table-driven; adding a new action type never modifies this
        method — only a new _handle_* method and a new entry in the dispatch table.
        """
        LOGGER.info("EngineCoordinator.run() started.")

        while True:
            try:
                request = self._io.collect_user_request()
            except (KeyboardInterrupt, EOFError):
                self._io._print("\n\nSession interrupted. Goodbye!")
                LOGGER.info("Session interrupted by user.")
                break

            action = request.get("action", "")

            if action == "exit":
                self._io._print("\nThank you for using the Cyber Threat Detection Engine. Stay safe!")
                LOGGER.info("User selected exit.")
                break

            elif action == "analyze_submission":
                input_type = request.get("input_type", "text")
                if input_type == "text":
                    self._handle_text_pipeline(request)
                else:
                    # url or file → VirusTotal pipeline
                    self._handle_resource_pipeline(request)

            elif action == "emerging_threat_radar":
                self._handle_threat_radar(request)

            elif action == "view_trending_threats":
                # IOManager already displayed the trending threats; loop continues
                pass

            elif action == "history_query":
                # IOManager already handled the history query interactively; loop continues
                pass

            else:
                LOGGER.warning("Unknown action received from IOManager: %s", action)

    # -------------------------------------------------------------------------
    # Pipeline: Text / Scam Message Analysis
    # -------------------------------------------------------------------------

    def _handle_text_pipeline(self, request: dict) -> None:
        """Run ordinary text analysis through the shared pipeline."""
        submission = Submission(
            input_type="text",
            input_value=request.get("input_value", ""),
            interaction_type=request.get(
                "interaction_type",
                "viewed_only",
            ),
            interaction_description=request.get(
                "interaction_description"
            ),
            input_hash=request.get("input_hash", ""),
        )

        result = self._process_text_submission(submission)

        if result["success"]:
            self._io.display_assessment(submission)
        else:
            self._io._print(
                f"\n[Analysis] {result['error']}"
            )

    def _process_text_submission(
        self,
        submission: Submission,
        *,
        email=None,
    ) -> dict:
        """Process one text submission without terminal output.

        Batch and ordinary text analysis share this implementation.
        Database failures are returned separately from analysis failures.
        """
        submission_id = None

        try:
            submission_id = self._data.save_submission(submission)

            if email is not None:
                self._data.link_submission_to_batch(
                    submission.dataset_batch,
                    submission_id,
                )
                self._data.save_email_metadata(
                    submission_id,
                    email,
                )

            submission.mark_processing()
            self._data.save_submission(submission)

            ai_arguments = {
                "text": submission.input_value,
                "interaction": submission.interaction_type,
                "interaction_description": (
                    submission.interaction_description
                ),
            }

            if email is not None:
                # Keep the existing Submission interaction vocabulary.
                # Explicitly report unknown exposure to the AI.
                ai_arguments["interaction"] = "unknown"
                ai_arguments["include_scenarios"] = True

            ai_result = self._ai.analyze_message(**ai_arguments)

            if not isinstance(ai_result, dict):
                raise ValueError(
                    "AI returned an invalid analysis response."
                )

            if "error" in ai_result:
                raise ValueError(
                    str(ai_result.get("error") or "AI analysis failed.")
                )

            # Save the complete AI output, including batch recovery guidance.
            self._data.save_text_analysis(
                submission_id,
                ai_result,
                self._get_model_name(),
            )

            indicators = ai_result.get("indicators", {})

            if not isinstance(indicators, dict):
                raise ValueError("AI indicators must be an object.")

            for indicator_name, indicator_data in indicators.items():
                if not isinstance(indicator_data, dict):
                    continue

                if indicator_data.get("present") is not True:
                    continue

                evidence_text = str(
                    indicator_data.get("evidence", "")
                ).strip()

                severity = "medium"

                if indicator_name in {
                    "payment_request",
                    "credential_request",
                    "otp_request",
                    "download_request",
                }:
                    severity = "high"

                submission.create_evidence(
                    name=indicator_name,
                    source="gemini",
                    evidence_type="indicator",
                    evidence_value=evidence_text or None,
                    excerpt=(
                        evidence_text[:200]
                        if evidence_text
                        else None
                    ),
                    severity=severity,
                )

            # Preserve the existing business rules.
            assessment = self._logic.evaluate_text_threat(
                submission,
                ai_result,
            )

            submission.set_assessment(assessment)

            self._data.save_assessment(
                submission_id,
                assessment,
                self._get_model_name(),
            )

            # save_submission already saves the attached assessment
            # and evidence together.
            submission.mark_completed()
            self._data.save_submission(submission)

            return {
                "success": True,
                "submission_id": submission_id,
                "error": None,
                "database_error": False,
            }

        except DataManagerError as error:
            LOGGER.exception(
                "Persistence failed for submission %s.",
                submission_id,
            )

            # Do not claim completion when persistence failed.
            return {
                "success": False,
                "submission_id": submission_id,
                "error": str(error),
                "database_error": True,
            }

        except Exception as error:
            LOGGER.exception(
                "Analysis failed for submission %s.",
                submission_id,
            )

            submission.mark_failed(str(error))
            database_error = False

            if submission_id is not None:
                try:
                    self._data.save_submission(submission)
                except DataManagerError:
                    database_error = True
                    LOGGER.exception(
                        "Could not persist failure for submission %s.",
                        submission_id,
                    )

            return {
                "success": False,
                "submission_id": submission_id,
                "error": str(error),
                "database_error": database_error,
            }

    # -------------------------------------------------------------------------
    # Pipeline: URL / File Resource Analysis (VirusTotal)
    # -------------------------------------------------------------------------

    def _handle_batch_pipeline(self, request: dict) -> dict:
        """Import and process a batch sequentially using shared analysis.

        Returns data for IOManager to display.
        Threading and report generation are separate integrations.
        """
        if self._ingestion is None:
            raise RuntimeError(
                "Email ingestion service has not been configured."
            )

        import_result = self._ingestion.ingest_paths(
            request.get("paths", [])
        )

        accepted = import_result["accepted"]
        issues = import_result["issues"]

        duplicate_count = 0
        import_failed_count = 0

        for issue in issues:
            if issue["kind"] == "duplicate":
                duplicate_count += 1
            else:
                import_failed_count += 1

        batch_reference = self._data.create_email_batch(
            total_files=(
                len(accepted)
                + duplicate_count
                + import_failed_count
            ),
            accepted_count=len(accepted),
            duplicate_count=duplicate_count,
            import_failed_count=import_failed_count,
        )

        self._data.save_batch_import_issues(
            batch_reference,
            issues,
        )

        self._data.update_email_batch_status(
            batch_reference,
            "processing",
        )

        results = []

        for email in accepted:
            # Include available headers and attachment metadata in analysis.
            # This JSON is submitted data, not prompt instructions.
            analysis_content = json.dumps(
                {
                    "subject": email.subject,
                    "sender": email.sender,
                    "reply_to": email.reply_to,
                    "recipients": email.recipients,
                    "body_text": email.body_text,
                    "extracted_urls": email.urls,
                    "attachment_metadata": email.attachments,
                    "parsing_warnings": email.warnings,
                },
                ensure_ascii=False,
            )

            submission = Submission(
                input_type="text",
                input_value=analysis_content,
                interaction_type="other",
                interaction_description=(
                    "This email was imported for batch analysis. "
                    "Recipient actions are unknown and have not "
                    "been reported."
                ),
                file_path=email.source_path,
                data_origin="batch_email",
                dataset_batch=batch_reference,
            )

            result = self._process_text_submission(
                submission,
                email=email,
            )

            result["item_id"] = email.item_id
            results.append(result)

            # Stop if persistence is unreliable. AI/logic failures alone
            # do not stop subsequent emails.
            if result["database_error"]:
                break

        successful_count = 0
        analysis_failed_count = 0
        database_failed = False

        for result in results:
            if result["success"]:
                successful_count += 1
            else:
                analysis_failed_count += 1

            if result["database_error"]:
                database_failed = True

        unprocessed_count = len(accepted) - len(results)

        if database_failed or unprocessed_count > 0:
            final_status = "failed"
        elif not accepted:
            final_status = "failed"
        elif successful_count == 0:
            final_status = "failed"
        elif analysis_failed_count > 0 or import_failed_count > 0:
            final_status = "partially_failed"
        else:
            final_status = "completed"

        status_saved = False
        status_error = None

        try:
            self._data.update_email_batch_status(
                batch_reference,
                final_status,
            )
            status_saved = True

        except DataManagerError as error:
            status_error = str(error)

            LOGGER.exception(
                "Could not save final status for batch %s.",
                batch_reference,
            )

        return {
            "batch_reference": batch_reference,
            "accepted_count": len(accepted),
            "duplicate_count": duplicate_count,
            "import_failed_count": import_failed_count,
            "issues": issues,
            "results": results,
            "unprocessed_count": unprocessed_count,
            "successful_count": successful_count,
            "analysis_failed_count": analysis_failed_count,
            "processing_status": final_status,
            "status_saved": status_saved,
            "status_error": status_error,
        }

    def _handle_resource_pipeline(self, request: dict) -> None:
        """Orchestrate the VirusTotal URL/file analysis pipeline.

        Steps:
        1. Create Submission and persist as pending.
        2. Transition to processing.
        3. Call VirusTotalScanner.scan_resource().
        4. On scanner error → mark failed, persist, display error, return.
        5. Extract technical evidence from VirusTotal findings.
        6. Call AIManager.analyze_technical_threat() on the parsed VT result.
           Every URL/file record must pass through the AI: on AI error → mark
           failed, persist, display error, return.
        7. Call LogicManager.evaluate_technical_threat() with BOTH the VT result
           and the AI result, so the AI verdict influences the risk decision.
        8. Attach the AI's educational guidance to the assessment.
        9. Persist assessment, evidence, VT telemetry and AI analysis.
        10. Mark completed, persist, and display via IOManager.display_assessment().
        """
        input_type = request.get("input_type", "url")
        input_value = request.get("input_value", "")
        file_path = request.get("file_path")
        interaction_type = request.get("interaction_type", "viewed_only")
        interaction_description = request.get("interaction_description")
        input_hash = request.get("input_hash", "")

        # Step 1: Create and save Submission
        submission = Submission(
            input_type=input_type,
            input_value=input_value,
            interaction_type=interaction_type,
            interaction_description=interaction_description,
            input_hash=input_hash,
            file_path=file_path,
        )
        try:
            submission_id = self._data.save_submission(submission)
            submission.submission_id = submission_id
        except DataManagerError as db_err:
            LOGGER.error("Failed to persist initial submission: %s", db_err)
            self._io._print(f"\n[Database] Could not save submission: {db_err}")
            return

        # Step 2: Mark processing
        submission.mark_processing()
        self._safe_update_submission(submission)

        # Step 3: VirusTotal scan
        if self._scanner is None:
            error_msg = "No threat scanner is configured. Cannot analyse URL/file resources."
            LOGGER.error(error_msg)
            submission.mark_failed(error_msg)
            self._safe_update_submission(submission)
            self._io._print(f"\n[Scanner] {error_msg}")
            return

        scan_target = file_path if (input_type == "file" and file_path) else input_value
        LOGGER.info(
            "Sending submission #%d to VirusTotalScanner.",
            submission_id,
        )
        vt_result = self._scanner.scan_resource(input_type, scan_target)

        # Step 4: Handle scanner failure
        if not isinstance(vt_result, dict) or "error" in vt_result:
            error_msg = (
                vt_result.get("error", "Unknown scanner error.")
                if isinstance(vt_result, dict)
                else "Scanner returned an invalid response."
            )
            LOGGER.error("Scanner failed for submission #%d: %s", submission_id, error_msg)
            submission.mark_failed(error_msg)
            self._safe_update_submission(submission)
            self._io._print(f"\n[Scanner] Scan failed: {error_msg}")
            return

        parsed_result = vt_result.get("parsed_result", {})

        # Step 5: Extract technical evidence from VirusTotal findings
        for threat_name in parsed_result.get("threat_names", []):
            submission.create_evidence(
                name=threat_name,
                source="virustotal",
                evidence_type="detection",
                evidence_value=threat_name,
                severity="high",
            )

        # Step 6: AI technical analysis (mandatory; runs BEFORE the risk decision)
        LOGGER.info("Sending submission #%d to AIManager for technical analysis.", submission_id)
        ai_result = self._ai.analyze_technical_threat(
            vt_data=parsed_result,
            interaction=interaction_type,
            interaction_description=interaction_description,
        )
        if not isinstance(ai_result, dict) or "error" in ai_result:
            error_msg = (
                ai_result.get("error", "Unknown AI error.")
                if isinstance(ai_result, dict)
                else "AI returned an invalid response."
            )
            LOGGER.error("AIManager failed for submission #%d: %s", submission_id, error_msg)
            submission.mark_failed(error_msg)
            self._safe_update_submission(submission)
            self._io._print(f"\n[AI Analysis] Analysis failed: {error_msg}")
            return

        # Step 7: Business rule evaluation using VT data AND the AI verdict
        try:
            assessment = self._logic.evaluate_technical_threat(submission, parsed_result, ai_result)
        except (TypeError, ValueError) as logic_err:
            LOGGER.error("LogicManager failed for submission #%d: %s", submission_id, logic_err)
            submission.mark_failed(str(logic_err))
            self._safe_update_submission(submission)
            self._io._print(f"\n[Risk Analysis] Risk evaluation failed: {logic_err}")
            return

        # Step 8: Attach the AI's educational guidance from the same response
        education = ai_result.get("education", {})
        if isinstance(education, dict):
            assessment.attach_educational_guidance(
                what_it_is=education.get("what_it_is"),
                threat_summary=education.get("threat_summary"),
                recovery_steps=education.get("recovery_steps"),
            )

        # Step 9: Persist assessment, evidence, scanner telemetry and AI analysis
        model_name = self._get_model_name()
        try:
            self._data.save_assessment(submission_id, assessment, model_name)
            self._data.save_evidences(submission_id, submission.evidences)
            self._data.save_vt_scan_result(submission_id, vt_result)
            self._data.save_technical_analysis(submission_id, ai_result, model_name)
        except DataManagerError as db_err:
            LOGGER.error("Failed to persist assessment for submission #%d: %s", submission_id, db_err)
            self._io._print(f"\n[Database] Results could not be saved: {db_err}")

        # Step 10: Mark completed, persist and display
        submission.mark_completed()
        self._safe_update_submission(submission)
        LOGGER.info("Submission #%d (resource) completed successfully.", submission_id)

        self._io.display_assessment(submission)

    # -------------------------------------------------------------------------
    # Pipeline: Emerging Threat Radar
    # -------------------------------------------------------------------------

    def _handle_threat_radar(self, request: dict) -> None:
        """Fetch live emerging threat intelligence and display it.

        Steps:
        1. Extract topic from request dict (may be None for broad scan).
        2. Call AIManager.fetch_emerging_radar(topic).
        3. Display result via IOManager.display_threat_radar() if available,
           else fallback to a plain-text summary print.
        """
        topic: Optional[str] = request.get("topic")
        LOGGER.info("Fetching emerging threat radar. Topic: %s", topic or "(all)")

        radar_result = self._ai.fetch_emerging_radar(topic=topic)

        if not isinstance(radar_result, dict) or "error" in radar_result:
            error_msg = (
                radar_result.get("error", "Unknown radar error.")
                if isinstance(radar_result, dict)
                else "Radar returned an invalid response."
            )
            self._io._print(f"\n[Threat Radar] Could not fetch threat intelligence: {error_msg}")
            return

        if hasattr(self._io, "display_threat_radar"):
            try:
                self._io.display_threat_radar(radar_result, topic=topic)
            except TypeError:
                self._io.display_threat_radar(radar_result)
        else:
            # Graceful fallback if IOManager lacks the display method
            content = radar_result.get("content", "No content available.")
            sources = radar_result.get("sources", [])
            self._io._print("\n" + "=" * 72)
            self._io._print("🌐  EMERGING THREAT RADAR REPORT")
            self._io._print("=" * 72)
            self._io._print(content)
            if sources:
                self._io._print("\nSources:")
                for src in sources:
                    title = src.get("title", "Unnamed source")
                    url = src.get("url", "")
                    self._io._print(f"  • {title}: {url}")
            self._io._print("=" * 72)

    # -------------------------------------------------------------------------
    # Private Helpers
    # -------------------------------------------------------------------------

    def _safe_update_submission(self, submission: Submission) -> None:
        """Persist a submission status update, swallowing DB errors to avoid masking pipeline errors."""
        try:
            self._data.save_submission(submission)
        except (DataManagerError, ValueError) as db_err:
            LOGGER.warning(
                "Could not persist status update for submission #%s: %s",
                submission.submission_id,
                db_err,
            )

    def _get_model_name(self) -> str:
        """Safely retrieve the active LLM model name for audit logging."""
        try:
            return self._ai.llm_client.model_name
        except Exception:
            return "unknown"
