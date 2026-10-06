"""
Test logic_manager with fixed AI and VirusTotal responses.

Covers text, URL and file assessments, all six user interaction
choices, response routing, invalid evidence and overall risk
combinations.

User actions are supplied directly to logic_manager. This script
does not test interactive input_manager menus.

No live APIs or database access are used.

Run:
    python test_logic_manager.py
"""

import sys

import logic_manager as logic


def make_ai_response(active=None):
    """Create a complete fixed AI response."""
    if active is None:
        active = {}

    names = (
        "urgency_pressure",
        "authority_impersonation",
        "credential_request",
        "personal_information_request",
        "payment_request",
        "otp_request",
        "suspicious_link",
        "download_request",
        "threatening_language",
        "reward_or_prize"
    )

    return {
        "message_classification": "uncertain",
        "indicators": {
            name: {
                "present": name in active,
                "evidence": active.get(name, "")
            }
            for name in names
        },
        "other_warning_signs": [],
        "user_exposure": {}
    }


def make_vt_response(
    resource_type,
    malicious=0,
    suspicious=0,
    undetected=70,
    timeout=0
):
    """Create a fixed parsed VirusTotal response."""
    return {
        "resource_type": resource_type,
        "detection_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": 0,
            "undetected": undetected,
            "timeout": timeout
        },
        "reputation": 0,
        "threat_names": [],
        "categories": []
    }


def check_equal(actual, expected, description="Result"):
    """Verify that an actual result matches the expected value."""
    if actual != expected:
        raise AssertionError(
            f"{description}: expected {expected!r}, "
            f"received {actual!r}"
        )


def check_value_error(function, *args):
    """Verify that invalid evidence is rejected."""
    try:
        function(*args)
    except ValueError:
        return

    raise AssertionError("Expected ValueError, but none was raised.")


def test_text_no_warnings():
    response = make_ai_response()
    result = logic.evaluate_text_risk(response, "viewed_only")

    check_equal(result["message_risk"], "low")
    check_equal(result["overall_risk"], "low")
    check_equal(result["is_scam"], False)


def test_text_phishing():
    response = make_ai_response({
        "credential_request": "Enter your password.",
        "suspicious_link": "Use this unverified login link."
    })
    result = logic.evaluate_text_risk(response, "viewed_only")

    check_equal(result["message_risk"], "high")
    check_equal(result["is_scam"], True)
    check_equal(
        "possible_credential_phishing" in result["flags"],
        True
    )


def test_text_payment_response():
    response = make_ai_response({
        "urgency_pressure": "Act within five minutes."
    })
    result = logic.evaluate_text_risk(
        response,
        "made_payment_or_shared_banking_details"
    )

    check_equal(result["overall_risk"], "high")
    check_equal(result["route"], "urgent_financial_response")
    check_equal(result["priority"], "urgent")


def test_url_no_detections():
    response = make_vt_response("url")
    result = logic.evaluate_vt_risk(response, "clicked_link")

    check_equal(result["technical_risk"], "low")
    check_equal(result["exposure_level"], "medium")
    check_equal(result["overall_risk"], "low")


def test_url_suspicious():
    response = make_vt_response("url", suspicious=2)
    result = logic.evaluate_vt_risk(response, "viewed_only")

    check_equal(result["technical_risk"], "medium")
    check_equal(result["route"], "verification_guidance")


def test_file_malicious_and_opened():
    response = make_vt_response("file", malicious=8)
    response["threat_names"] = ["trojan"]
    result = logic.evaluate_vt_risk(
        response,
        "opened_or_downloaded_file"
    )

    check_equal(result["technical_risk"], "high")
    check_equal(result["route"], "device_security_response")
    check_equal("trojan" in result["flags"], True)


def test_file_malicious_but_viewed_only():
    response = make_vt_response("file", malicious=8)
    result = logic.evaluate_vt_risk(response, "viewed_only")

    check_equal(result["exposure_level"], "low")
    check_equal(result["route"], "high_risk_guidance")


def test_text_missing_indicators():
    check_value_error(
        logic.evaluate_text_risk,
        {},
        "viewed_only"
    )


def test_text_missing_one_indicator():
    response = make_ai_response()
    del response["indicators"]["otp_request"]

    check_value_error(
        logic.evaluate_text_risk,
        response,
        "viewed_only"
    )


def test_text_missing_evidence():
    response = make_ai_response({
        "credential_request": ""
    })

    check_value_error(
        logic.evaluate_text_risk,
        response,
        "viewed_only"
    )


def test_text_ai_error():
    check_value_error(
        logic.evaluate_text_risk,
        {"error": "AI unavailable."},
        "viewed_only"
    )


def test_vt_timeout_only():
    for resource_type in ("url", "file"):
        response = make_vt_response(
            resource_type,
            undetected=0,
            timeout=10
        )

        check_value_error(
            logic.evaluate_vt_risk,
            response,
            "viewed_only"
        )


def test_vt_empty_statistics():
    check_value_error(
        logic.evaluate_vt_risk,
        {"detection_stats": {}},
        "viewed_only"
    )


def test_vt_negative_counts():
    response = make_vt_response("url", malicious=-1)

    check_value_error(
        logic.evaluate_vt_risk,
        response,
        "viewed_only"
    )


def test_vt_invalid_number():
    response = make_vt_response("url")
    response["detection_stats"]["malicious"] = "invalid"

    check_value_error(
        logic.evaluate_vt_risk,
        response,
        "viewed_only"
    )


def test_vt_timeouts_excluded_from_ratio():
    response = make_vt_response(
        "url",
        malicious=1,
        undetected=9,
        timeout=90
    )
    result = logic.evaluate_vt_risk(response, "viewed_only")

    # One detection / ten completed assessments = 10%.
    check_equal(result["detection_ratio"], 10.0)
    check_equal(result["technical_risk"], "high")


def test_overall_risk_matrix():
    cases = (
        ("low", "low", "low"),
        ("low", "medium", "low"),
        ("low", "high", "low"),
        ("medium", "low", "medium"),
        ("medium", "medium", "medium"),
        ("medium", "high", "high"),
        ("high", "low", "high"),
        ("high", "medium", "high"),
        ("high", "high", "high")
    )

    for message_level, exposure_level, expected in cases:
        result = logic.determine_overall_risk(
            message_level,
            exposure_level
        )
        check_equal(
            result,
            expected,
            f"Risk combination {message_level}/{exposure_level}"
        )


def test_all_six_interaction_choices():
    """Check exposure levels for every interaction choice."""
    cases = (
        ("viewed_only", {}, "low"),
        ("clicked_link", {}, "medium"),
        ("entered_information", {}, "high"),
        ("opened_or_downloaded_file", {}, "high"),
        ("made_payment_or_shared_banking_details", {}, "high"),
        ("other", {"shared_otp": True}, "high")
    )

    for interaction_type, user_exposure, expected_level in cases:
        result = logic.determine_user_exposure(
            interaction_type,
            user_exposure
        )

        check_equal(
            result["level"],
            expected_level,
            f"Exposure for {interaction_type}"
        )


def test_text_routes_for_all_six_actions():
    """Check each interaction choice on a phishing message."""
    cases = (
        ("viewed_only", {}, "high_risk_guidance"),
        ("clicked_link", {}, "high_risk_guidance"),
        ("entered_information", {}, "account_security_response"),
        (
            "opened_or_downloaded_file",
            {},
            "device_security_response"
        ),
        (
            "made_payment_or_shared_banking_details",
            {},
            "urgent_financial_response"
        ),
        (
            "other",
            {"shared_otp": True},
            "urgent_financial_response"
        )
    )

    for interaction_type, user_exposure, expected_route in cases:
        response = make_ai_response({
            "credential_request": "Enter your account password.",
            "suspicious_link": "Use this unverified login link."
        })
        response["user_exposure"] = user_exposure

        result = logic.evaluate_text_risk(
            response,
            interaction_type
        )

        check_equal(
            result["overall_risk"],
            "high",
            f"Text risk for {interaction_type}"
        )
        check_equal(
            result["route"],
            expected_route,
            f"Text route for {interaction_type}"
        )


def test_url_and_file_routes_for_all_six_actions():
    """Check both VirusTotal workflows with every action."""
    cases = (
        ("viewed_only", {}, "high_risk_guidance"),
        ("clicked_link", {}, "high_risk_guidance"),
        ("entered_information", {}, "account_security_response"),
        (
            "opened_or_downloaded_file",
            {},
            "device_security_response"
        ),
        (
            "made_payment_or_shared_banking_details",
            {},
            "urgent_financial_response"
        ),
        (
            "other",
            {"shared_otp": True},
            "urgent_financial_response"
        )
    )

    for resource_type in ("url", "file"):
        for interaction_type, user_exposure, expected_route in cases:
            response = make_vt_response(
                resource_type,
                malicious=8
            )

            result = logic.evaluate_vt_risk(
                response,
                interaction_type,
                user_exposure
            )

            check_equal(
                result["overall_risk"],
                "high",
                f"{resource_type} risk for {interaction_type}"
            )
            check_equal(
                result["route"],
                expected_route,
                f"{resource_type} route for {interaction_type}"
            )


def run_tests():
    """Run all tests and return a success or failure exit code."""
    tests = (
        test_text_no_warnings,
        test_text_phishing,
        test_text_payment_response,
        test_url_no_detections,
        test_url_suspicious,
        test_file_malicious_and_opened,
        test_file_malicious_but_viewed_only,
        test_text_missing_indicators,
        test_text_missing_one_indicator,
        test_text_missing_evidence,
        test_text_ai_error,
        test_vt_timeout_only,
        test_vt_empty_statistics,
        test_vt_negative_counts,
        test_vt_invalid_number,
        test_vt_timeouts_excluded_from_ratio,
        test_overall_risk_matrix,
        test_all_six_interaction_choices,
        test_text_routes_for_all_six_actions,
        test_url_and_file_routes_for_all_six_actions
    )
    failed = 0

    print("LOGIC MANAGER OFFLINE TESTS")
    print("=" * 60)

    for test in tests:
        try:
            test()
        except Exception as error:
            failed += 1
            print(f"FAIL: {test.__name__}")
            print(f"      {type(error).__name__}: {error}")
        else:
            print(f"PASS: {test.__name__}")

    print("=" * 60)
    print(
        f"Total: {len(tests)} | "
        f"Passed: {len(tests) - failed} | Failed: {failed}"
    )

    if failed:
        print("RESULT: FAILED")
        return 1

    print("RESULT: ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())