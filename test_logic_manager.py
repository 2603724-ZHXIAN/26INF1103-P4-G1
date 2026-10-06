"""Test text, URL and file risk rules without live APIs."""

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


def make_vt_response(resource_type, malicious=0, suspicious=0,
                     undetected=70, timeout=0):
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


def check_equal(actual, expected):
    if actual != expected:
        raise AssertionError(
            f"Expected {expected!r}, received {actual!r}"
        )


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


def run_tests():
    tests = (
        test_text_no_warnings,
        test_text_phishing,
        test_text_payment_response,
        test_url_no_detections,
        test_url_suspicious,
        test_file_malicious_and_opened,
        test_file_malicious_but_viewed_only
    )
    failed = 0

    for test in tests:
        try:
            test()
        except Exception as error:
            failed += 1
            print(f"FAIL: {test.__name__}: {error}")
        else:
            print(f"PASS: {test.__name__}")

    print(
        f"Total: {len(tests)} | "
        f"Passed: {len(tests) - failed} | Failed: {failed}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(run_tests())