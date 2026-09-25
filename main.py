"""Coordinate input collection, analysis, and database storage."""

import logging

import db_manager as db
import gemini_manager as gemini
import logic_manager as logic
from config import DB_PATH
from input_manager import collect_user_request
import virustotal_manager as vt


logging.basicConfig(
    filename="cyber_threat_engine.log",
    level=logging.INFO,
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )
)


def save_submission(request_data):
    """Save a returned input-manager submission."""
    submission_id = db.insert_submission(
        DB_PATH,
        data_origin="cli",
        input_type=request_data["input_type"],
        input_value=request_data["input_value"],
        input_hash=request_data["input_hash"],
        file_path=request_data.get("file_path"),
        interaction_type=request_data["interaction_type"],
        interaction_description=request_data[
            "interaction_description"
        ],
        processing_status="pending"
    )

    return submission_id


def mark_submission_failed(submission_id, error_message):
    """Mark a submission as failed without hiding the original error."""
    try:
        db.update_submission_status(
            DB_PATH,
            submission_id,
            "failed",
            str(error_message)
        )
    except Exception:
        logging.exception(
            "Could not mark submission %s as failed",
            submission_id
        )


def get_gemini_model_name(default="education-unavailable"):
    """Return the configured Gemini model or a safe fallback."""
    try:
        _, model_name = gemini.load_gemini_config()
        return model_name
    except ValueError:
        return default


def format_label(value, default="unknown"):
    """Convert an internal snake-case value into a CLI label."""
    if value is None:
        value = default

    return str(value).replace("_", " ").strip().title()


def display_numbered_steps(steps, fallback_action):
    """Display numbered guidance steps with a fallback action."""
    if isinstance(steps, list) and steps:
        for step_number, step in enumerate(steps, start=1):
            print(f"{step_number}. {step}")
        return

    print(f"1. {fallback_action}")


def display_education(education, fallback_action):
    """Display education shared by text and VirusTotal workflows."""
    if not isinstance(education, dict):
        education = {}

    print("\nWHAT THIS THREAT MEANS")
    print("-" * 60)
    print(
        education.get(
            "what_it_is",
            education.get(
                "threat_summary",
                "No threat explanation is available."
            )
        )
    )

    print("\nWHAT YOU SHOULD DO NOW")
    print("-" * 60)
    display_numbered_steps(
        education.get("recovery_steps", []),
        fallback_action
    )


def display_vt_result(analysis_result):
    """Display a verified or unverified VT resource assessment."""
    vt_result = analysis_result.get("virustotal_analysis", {})
    risk_result = analysis_result.get("risk_assessment", {})
    education = analysis_result.get("education", {})
    stats = vt_result.get("detection_stats", {})
    report_url = analysis_result.get("report_url")
    assessment_status = analysis_result.get(
        "assessment_status",
        "completed"
    )
    resource_type = format_label(
        analysis_result.get(
            "resource_type",
            vt_result.get("resource_type", "resource")
        )
    )

    if assessment_status == "unverified":
        print("\n" + "=" * 60)
        print(f"UNVERIFIED {resource_type.upper()} ASSESSMENT")
        print("=" * 60)
        print(
            "VirusTotal status: "
            f"{analysis_result.get('virustotal_status', 'Unknown')}"
        )
        print(
            "Technical risk: "
            f"{format_label(risk_result.get('technical_risk'))}"
        )
        print(
            "Overall result: "
            f"{analysis_result.get('overall_result', 'Unverified')}"
        )

        observations = education.get("resource_observations", [])

        if not observations:
            summary = education.get("threat_summary", "")
            observations = [summary] if summary else []

        if observations:
            print("\nAI OBSERVATIONS")
            print("-" * 60)

            for observation in observations:
                print(f"- {observation}")

        print("\nYOUR REPORTED ACTION")
        print("-" * 60)
        print(
            risk_result.get(
                "exposure_reason",
                "No reported action was available."
            )
        )

        display_education(
            education,
            risk_result.get(
                "recommended_action",
                "Avoid the resource until it can be verified."
            )
        )

        if report_url:
            print("\nVirusTotal report:")
            print(report_url)

        print("=" * 60)
        return

    technical_risk = risk_result.get("technical_risk", "low")
    safe_result = technical_risk == "low"
    threat_names = vt_result.get("threat_names", [])
    categories = vt_result.get("categories", [])
    threat_candidates = threat_names or categories

    if safe_result:
        primary_threat = "None Detected"
    elif threat_candidates:
        primary_threat = format_label(threat_candidates[0])
    else:
        primary_threat = "No Specific Threat Identified"

    if risk_result.get("is_malicious", False):
        threat_status = "MALICIOUS"
    elif technical_risk == "medium":
        threat_status = "SUSPICIOUS"
    else:
        threat_status = "NO MALICIOUS DETECTIONS"

    print("\n" + "=" * 60)
    print(f"{resource_type.upper()} SECURITY ANALYSIS RESULT")
    print("=" * 60)
    print(f"Threat status: {threat_status}")
    print(
        "Risk level: "
        f"{format_label(risk_result.get('overall_risk')).upper()}"
    )
    print(f"Primary threat: {primary_threat}")

    if safe_result:
        meaning_heading = "WHAT THIS RESULT MEANS"
        action_heading = "ROUTINE SAFETY GUIDANCE"
    else:
        meaning_heading = "WHAT THIS THREAT MEANS"
        action_heading = "WHAT YOU SHOULD DO NOW"

    print(f"\n{meaning_heading}")
    print("-" * 60)
    print(
        education.get(
            "what_it_is",
            education.get(
                "threat_summary",
                "No threat explanation is available."
            )
        )
    )

    print("\nYOUR REPORTED ACTION")
    print("-" * 60)
    print(
        risk_result.get(
            "exposure_reason",
            "No reported action was available."
        )
    )

    print(f"\n{action_heading}")
    print("-" * 60)
    display_numbered_steps(
        education.get("recovery_steps", []),
        risk_result.get(
            "recommended_action",
            "Remain cautious and verify the resource."
        )
    )

    if report_url:
        print("\nVirusTotal report:")
        print(report_url)

    print("=" * 60)


def get_reported_action(request_data, gemini_result):
    """Return the interaction reported by the user."""
    interaction_type = str(
        request_data.get("interaction_type", "")
    )

    interaction_actions = {
        "viewed_only": "You viewed the message only.",
        "clicked_link": (
            "You clicked the link but did not report entering "
            "any information."
        ),
        "entered_information": (
            "You entered personal or login information."
        ),
        "opened_or_downloaded_file": (
            "You opened or downloaded a file."
        ),
        "made_payment_or_shared_banking_details": (
            "You made a payment or shared banking details."
        )
    }

    if interaction_type == "other":
        interaction_description = str(
            request_data.get("interaction_description", "")
        ).strip()

        if interaction_description:
            return f"You reported: {interaction_description}"

        return "You reported another type of interaction."

    gemini_exposure = gemini_result.get(
        "user_exposure",
        {}
    ).get("description_summary")

    if gemini_exposure:
        return gemini_exposure

    return interaction_actions.get(
        interaction_type,
        "Your interaction was not specified."
    )


def get_flag_reasons(risk_result):
    """Return user-friendly text or VirusTotal flag reasons."""
    indicator_evidence = risk_result.get(
        "indicator_evidence",
        []
    )

    reason_templates = {
        "reward_or_prize": "Promises a reward or prize: {evidence}",
        "urgency_pressure": "Creates urgency: {evidence}",
        "payment_request": (
            "Requests payment or payment information: {evidence}"
        ),
        "personal_information_request": (
            "Requests personal information: {evidence}"
        ),
        "credential_request": (
            "Requests login information: {evidence}"
        ),
        "otp_request": (
            "Requests an OTP or verification code: {evidence}"
        ),
        "suspicious_link": "Contains a suspicious link: {evidence}",
        "download_request": (
            "Encourages a file download or attachment: {evidence}"
        ),
        "authority_impersonation": (
            "May impersonate a trusted organisation: {evidence}"
        ),
        "threatening_language": (
            "Uses threatening language: {evidence}"
        )
    }

    flag_reasons = []

    for item in indicator_evidence:
        indicator = item.get("indicator", "")
        evidence = str(item.get("evidence", "")).strip()
        template = reason_templates.get(indicator)

        if not template:
            continue

        if evidence:
            reason = template.format(evidence=evidence)
        else:
            reason = format_label(indicator)

        if reason not in flag_reasons:
            flag_reasons.append(reason)

    if not flag_reasons:
        for reason in risk_result.get("message_reasons", []):
            if reason not in flag_reasons:
                flag_reasons.append(reason)

    if not flag_reasons:
        for reason in risk_result.get("risk_reasons", []):
            cleaned_reason = str(reason).strip()

            if cleaned_reason and cleaned_reason not in flag_reasons:
                flag_reasons.append(cleaned_reason)

    if not flag_reasons:
        for flag in risk_result.get("flags", []):
            cleaned_flag = format_label(flag)

            if cleaned_flag not in flag_reasons:
                flag_reasons.append(cleaned_flag)

    return flag_reasons


def show_flag_reasons_if_requested(risk_result):
    """Optionally display the reasons behind the scam decision."""
    while True:
        answer = input(
            "\nWould you like to know why it was flagged? "
            "(Y/N): > "
        ).strip().lower()

        if answer in ("n", "no"):
            return

        if answer in ("y", "yes"):
            print("\nWHY IT WAS FLAGGED")
            print("-" * 60)

            flag_reasons = get_flag_reasons(risk_result)

            if flag_reasons:
                for reason in flag_reasons:
                    print(f"- {reason}")
            else:
                print(
                    "- The analysis found suspicious characteristics "
                    "in the submitted message."
                )

            return

        print("Please enter Y or N.")


def display_text_result(gemini_result, risk_result, request_data):
    """Display a concise user-facing text-analysis result."""
    education = gemini_result.get("education", {})
    is_scam = bool(risk_result.get("is_scam", False))

    if is_scam:
        scam_status = "SCAM"
    else:
        classification = str(
            gemini_result.get("message_classification", "unknown")
        ).lower()

        if classification == "safe":
            scam_status = "NOT A SCAM"
        else:
            scam_status = "NOT CONFIRMED AS SCAM"

    risk_level = str(
        risk_result.get(
            "overall_risk",
            risk_result.get("risk_category", "unknown")
        )
    ).upper()

    confidence = str(
        gemini_result.get("analysis_confidence", "unknown")
    ).upper()

    primary_threat = format_label(
        gemini_result.get("primary_threat_type")
    )

    print("\n" + "=" * 60)
    print("SCAM ANALYSIS RESULT")
    print("=" * 60)
    print(f"Scam status: {scam_status}")
    print(f"Risk level: {risk_level}")
    print(f"Confidence: {confidence}")
    print(f"Primary threat: {primary_threat}")

    print("\nWHAT THIS THREAT MEANS")
    print("-" * 60)

    threat_explanations = education.get(
        "threat_explanations",
        []
    )

    if threat_explanations:
        for threat in threat_explanations:
            threat_name = format_label(
                threat.get("threat_type")
            )
            meaning = threat.get(
                "meaning",
                "No explanation is available."
            )
            print(f"{threat_name}: {meaning}")
    else:
        print(
            education.get(
                "what_it_is",
                "No threat explanation is available."
            )
        )

    print("\nYOUR REPORTED ACTION")
    print("-" * 60)
    print(get_reported_action(request_data, gemini_result))

    print("\nWHAT YOU SHOULD DO NOW")
    print("-" * 60)

    display_numbered_steps(
        education.get("recovery_steps", []),
        risk_result.get(
            "recommended_action",
            "Verify the message through an official channel."
        )
    )

    print("=" * 60)

    if is_scam:
        show_flag_reasons_if_requested(risk_result)


def analyse_text_submission(request_data, submission_id):
    """Analyse one text submission using Gemini and business rules."""
    print(
        "\n[Text Analysis] Sending the submitted text to Gemini..."
    )

    try:
        gemini_result = gemini.analyse_text_with_gemini(
            request_data["input_value"],
            request_data["interaction_type"],
            request_data.get("interaction_description")
        )
    except Exception as error:
        mark_submission_failed(submission_id, error)

        logging.exception(
            "Unexpected Gemini failure for submission %s",
            submission_id
        )

        print(
            "\n[Text Analysis] Gemini could not complete the "
            f"analysis: {error}"
        )

        return None

    if "error" in gemini_result:
        error_message = gemini_result.get(
            "error",
            "Unknown Gemini error."
        )

        mark_submission_failed(submission_id, error_message)

        logging.error(
            "Gemini analysis failed for submission %s: %s",
            submission_id,
            error_message
        )

        print(
            f"\n[Text Analysis] Analysis failed: "
            f"{error_message}"
        )

        if gemini_result.get("details"):
            print(
                f"[Text Analysis] Details: "
                f"{gemini_result['details']}"
            )

        return None

    try:
        risk_result = logic.evaluate_text_risk(
            gemini_result,
            request_data["interaction_type"]
        )
    except (ValueError, AttributeError, TypeError) as error:
        mark_submission_failed(submission_id, error)

        logging.exception(
            "Logic Manager rejected submission %s",
            submission_id
        )

        print(
            "\n[Risk Analysis] Gemini completed the analysis, "
            "but the Logic Manager could not complete the "
            f"risk assessment: {error}"
        )

        return None

    try:
        model_name = get_gemini_model_name()

        db.save_text_analysis_results(
            DB_PATH,
            submission_id,
            gemini_result,
            risk_result,
            model_name
        )

        logging.info(
            "Text analysis for submission %s was saved successfully",
            submission_id
        )

    except Exception as error:
        mark_submission_failed(submission_id, error)

        logging.exception(
            "Could not save analysis for submission %s",
            submission_id
        )

        print(
            "\n[Database] The analysis was completed, but the "
            f"results could not be saved: {error}"
        )

        return None

    combined_result = {
        "submission_id": submission_id,
        "gemini_analysis": gemini_result,
        "risk_assessment": risk_result
    }

    display_text_result(
        gemini_result,
        risk_result,
        request_data
    )

    return combined_result


def analyse_vt_submission(request_data, submission_id):
    """Analyse a file or URL using VirusTotal."""
    input_type = request_data["input_type"]
    input_value = request_data["input_value"]

    if input_type == "file":
        input_value = request_data.get("file_path", input_value)

    print(
        f"\n[VirusTotal] Checking the submitted "
        f"{input_type}..."
    )

    try:
        vt_result = vt.scan_resource(
            input_type,
            input_value
        )
    except Exception as error:
        mark_submission_failed(submission_id, error)
        logging.exception(
            "Unexpected VirusTotal failure for submission %s",
            submission_id
        )
        print(
            "\n[VirusTotal] The scan could not be completed: "
            f"{error}"
        )
        return None

    if not isinstance(vt_result, dict):
        error_message = "VirusTotal returned an invalid result."
        mark_submission_failed(submission_id, error_message)
        print(f"\n[VirusTotal] Analysis failed: {error_message}")
        return None

    if "error" in vt_result:
        error_message = vt_result["error"]

        mark_submission_failed(submission_id, error_message)

        print(
            f"\n[VirusTotal] Analysis failed: "
            f"{error_message}"
        )

        if vt_result.get("details"):
            print(
                f"[VirusTotal] Details: "
                f"{vt_result['details']}"
            )

        return None

    parsed_result = vt_result["parsed_result"]
    interpreted_exposure = None

    if request_data["interaction_type"] == "other":
        print(
            "\n[Exposure Analysis] Interpreting the reported "
            "action with Gemini..."
        )

        try:
            interpreted_exposure = (
                gemini.analyse_other_interaction(
                    request_data.get("interaction_description")
                )
            )
        except Exception as error:
            logging.exception(
                "Unexpected exposure-interpretation failure "
                "for submission %s",
                submission_id
            )
            interpreted_exposure = {
                "error": (
                    "Gemini could not interpret the reported "
                    "interaction."
                ),
                "details": str(error)
            }

        if (
            not isinstance(interpreted_exposure, dict)
            or "error" in interpreted_exposure
        ):
            print(
                "\n[Exposure Analysis] The reported action "
                "could not be interpreted reliably. A "
                "conservative risk level will be used."
            )
            interpreted_exposure = None

    try:
        risk_result = logic.evaluate_vt_risk(
            parsed_result,
            request_data["interaction_type"],
            interpreted_exposure
        )
    except (AttributeError, TypeError, ValueError) as error:
        mark_submission_failed(submission_id, error)

        print(
            f"\n[Risk Analysis] Unable to assess "
            f"VirusTotal risk: {error}"
        )

        return None

    print(
        "\n[Education] Sending VirusTotal evidence "
        "to Gemini..."
    )

    try:
        education_result = gemini.analyse_vt_for_education(
            vt_result,
            risk_result,
            request_data["interaction_type"],
            request_data.get("interaction_description")
        )
    except Exception as error:
        logging.exception(
            "Unexpected Gemini education failure for submission %s",
            submission_id
        )
        education_result = {
            "error": "Gemini education failed unexpectedly.",
            "details": str(error)
        }

    if "error" in education_result:
        print(
            f"\n[Education] Gemini was unavailable: "
            f"{education_result['error']}"
        )

        print(
            "[Education] VirusTotal and Logic Manager results "
            "will still be saved."
        )

    try:
        model_name = get_gemini_model_name()

        save_result = db.save_vt_analysis_results(
            DB_PATH,
            submission_id,
            vt_result,
            risk_result,
            education_result,
            interpreted_exposure,
            model_name
        )
    except Exception as error:
        mark_submission_failed(submission_id, error)

        logging.exception(
            "Could not save VirusTotal analysis "
            "for submission %s",
            submission_id
        )

        print(
            "\n[Database] VirusTotal analysis completed, "
            f"but it could not be saved: {error}"
        )

        return None

    stored_education = education_result

    if not save_result.get("education_saved"):
        stored_education = db.build_fallback_vt_education(
            education_result.get(
                "error",
                "Gemini education was unavailable."
            )
        )

    combined_result = {
        "submission_id": submission_id,
        "assessment_status": "completed",
        "resource_type": input_type,
        "virustotal_analysis": parsed_result,
        "risk_assessment": risk_result,
        "education": stored_education,
        "report_url": vt_result.get("report_url")
    }

    display_vt_result(combined_result)

    return combined_result


def display_submission_outcome(
    analysis_name,
    submission_id,
    analysis_result
):
    """Display the common completion message for an analysis workflow."""
    if analysis_result is None:
        print(
            f"[{analysis_name}] The submission remains saved, "
            "but its analysis was not completed."
        )
        return

    print(
        f"\n[{analysis_name}] Submission #{submission_id} "
        "was analysed successfully."
    )


def process_request(request_data):
    """Route the returned input-manager request."""
    if request_data is None:
        return True

    action = request_data.get("action")

    if action == "exit":
        print(
            "\nThank you for using the Cyber Threat & Scam "
            "Detection Engine. Stay alert and stay secure."
        )
        return False

    if action == "analyze_submission":
        try:
            submission_id = save_submission(request_data)
        except (KeyError, TypeError, ValueError) as error:
            print(
                f"\n[Database] Invalid submission data: {error}"
            )
            return True
        except Exception as error:
            print(
                f"\n[Database] Could not save submission: {error}"
            )
            return True

        print(
            f"\n[Database] Submission #{submission_id} "
            "was saved successfully."
        )

        if request_data["input_type"] == "text":
            analysis_result = analyse_text_submission(
                request_data,
                submission_id
            )
            analysis_name = "Text Analysis"

        elif request_data["input_type"] in {"url", "file"}:
            analysis_result = analyse_vt_submission(
                request_data,
                submission_id
            )
            analysis_name = "VirusTotal"

        else:
            error_message = (
                "Unsupported input type: "
                f"{request_data['input_type']}"
            )
            mark_submission_failed(submission_id, error_message)
            print(f"\n[Analysis] {error_message}")
            return True

        display_submission_outcome(
            analysis_name,
            submission_id,
            analysis_result
        )

        return True

    if action == "history_query":
        print("\nHistorical query received:")
        print(request_data)
        return True

    if action == "view_trending_threats":
        print("\nTrending-threat request received.")
        return True

    print("\nUnknown action received.")
    return True


def main():
    """Run the complete application coordinator."""
    try:
        db.create_tables(DB_PATH)
    except Exception as error:
        print(
            f"\n[Database] Could not initialise the database: "
            f"{error}"
        )
        return

    application_running = True

    while application_running:
        try:
            request_data = collect_user_request()

            application_running = process_request(
                request_data
            )

        except KeyboardInterrupt:
            print(
                "\n\nSession interrupted. Thank you for using "
                "the Cyber Threat & Scam Detection Engine. "
                "Stay alert and stay secure."
            )
            application_running = False

        except EOFError:
            print(
                "\n\nThe input stream was closed. "
                "The application will now exit safely."
            )
            application_running = False

        except Exception as error:
            logging.exception(
                "Unexpected application error: %s",
                error
            )
            print(
                "\n[Application] An unexpected error occurred. "
                "The incident was logged and the application "
                "will continue."
            )


if __name__ == "__main__":
    main()
