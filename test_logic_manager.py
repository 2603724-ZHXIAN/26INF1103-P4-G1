"""Eighteen offline tests of logic_manager using hardcoded responses.

Six text cases use fixed parsed AI responses. Twelve URL/file cases use
fixed parsed VirusTotal responses, matching the evaluator input format.

Run from the folder containing logic_manager.py:
    python test_logic_manager.py

No Gemini, VirusTotal, database or network calls are made.
"""

import sys

import logic_manager as logic


def make_ai_response(active):
    """Build a fixed parsed AI response with all required indicators."""
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


def get_test_cases():
    """Define sample evidence and independent expected results."""
    return [
        {
            "name": "No warning indicators",
            "active": {},
            "interaction": "viewed_only",
            "expected": {
                "message_risk": "low",
                "overall_risk": "low",
                "is_scam": False
            },
            "explanation": "No warning indicators means low message risk."
        },
        {
            "name": "Credentials requested through a suspicious link",
            "active": {
                "credential_request": "Enter your account password.",
                "suspicious_link": "Sign in using this unverified link."
            },
            "interaction": "viewed_only",
            "expected": {
                "message_risk": "high",
                "overall_risk": "high",
                "is_scam": True
            },
            "explanation": (
                "Credentials + suspicious link trigger the high-risk "
                "phishing rule."
            )
        },
        {
            "name": "Authority impersonation and urgency",
            "active": {
                "authority_impersonation": "I am contacting you from your bank.",
                "urgency_pressure": "Act within five minutes."
            },
            "interaction": "viewed_only",
            "expected": {
                "message_risk": "medium",
                "overall_risk": "medium",
                "route": "verification_guidance"
            },
            "explanation": (
                "Impersonation + urgency trigger the medium-risk "
                "social engineering rule."
            )
        },
        {
            "name": "Suspicious message and payment made",
            "active": {
                "authority_impersonation": "I am contacting you from your bank.",
                "urgency_pressure": "Act within five minutes."
            },
            "interaction": "made_payment_or_shared_banking_details",
            "expected": {
                "message_risk": "medium",
                "exposure_level": "high",
                "overall_risk": "high",
                "route": "urgent_financial_response",
                "priority": "urgent"
            },
            "explanation": (
                "Medium message risk + payment exposure produce high "
                "overall risk and an urgent financial response."
            )
        },
        {
            "name": "Phishing message and information entered",
            "active": {
                "credential_request": "Enter your account password.",
                "suspicious_link": "Sign in using this unverified link."
            },
            "interaction": "entered_information",
            "expected": {
                "message_risk": "high",
                "exposure_level": "high",
                "overall_risk": "high",
                "route": "account_security_response"
            },
            "explanation": (
                "Entering information after a phishing message requires "
                "an account security response."
            )
        },
        {
            "name": "Required indicator missing",
            "active": {},
            "interaction": "viewed_only",
            "remove_indicator": "otp_request",
            "expected_error": ValueError,
            "explanation": (
                "Incomplete AI evidence must be rejected rather than "
                "assigned a low risk."
            )
        }
    ]


def get_vt_test_cases():
    """Test each action with fixed URL and file evidence."""
    responses = {
        "url": {
            "resource_type": "url",
            "detection_stats": {
                "malicious": 0, "suspicious": 2, "harmless": 0,
                "undetected": 68, "timeout": 0
            },
            "reputation": 0,
            "threat_names": [],
            "categories": []
        },
        "file": {
            "resource_type": "file",
            "detection_stats": {
                "malicious": 8, "suspicious": 0, "harmless": 0,
                "undetected": 62, "timeout": 0
            },
            "reputation": 0,
            "threat_names": ["trojan"],
            "categories": []
        }
    }
    # Expectations are fixed here, not calculated using logic_manager.
    actions = (
        ("viewed_only", {}, "low",
         "verification_guidance", "high_risk_guidance"),
        ("clicked_link", {}, "medium",
         "verification_guidance", "high_risk_guidance"),
        ("entered_information", {}, "high",
         "account_security_response", "account_security_response"),
        ("opened_or_downloaded_file", {}, "high",
         "device_security_response", "device_security_response"),
        ("made_payment_or_shared_banking_details", {}, "high",
         "urgent_financial_response", "urgent_financial_response"),
        ("other", {"shared_otp": True}, "high",
         "urgent_financial_response", "urgent_financial_response")
    )
    explanations = {
        "viewed_only": "Viewing only gives low exposure; source risk remains.",
        "clicked_link": "Clicking gives medium exposure; source risk remains.",
        "entered_information": (
            "Information entry gives high exposure and an account response."
        ),
        "opened_or_downloaded_file": (
            "Opening or downloading gives high exposure and a device response."
        ),
        "made_payment_or_shared_banking_details": (
            "Payment or banking details require an urgent financial response."
        ),
        "other": "The fixed Other description reports sharing an OTP."
    }
    cases = []
    for resource_type, response in responses.items():
        for action, exposure, level, url_route, file_route in actions:
            source_risk = "medium" if resource_type == "url" else "high"
            overall = (
                "medium"
                if resource_type == "url" and level in {"low", "medium"}
                else "high"
            )
            route = url_route if resource_type == "url" else file_route
            priority = (
                "urgent" if route == "urgent_financial_response"
                else "medium" if route == "verification_guidance"
                else "high"
            )
            cases.append({
                "name": f"{resource_type.upper()} - {action}",
                "response": response,
                "interaction": action,
                "user_exposure": exposure,
                "expected": {
                    "technical_risk": source_risk,
                    "detection_ratio": 2.86 if resource_type == "url" else 11.43,
                    "exposure_level": level,
                    "overall_risk": overall,
                    "is_malicious": resource_type == "file",
                    "route": route,
                    "priority": priority
                },
                "explanation": explanations[action]
            })
    return cases


def run_case(case, number):
    """Call the actual evaluator, print results and verify expectations."""
    print(f"\nTEST {number}: {case['name']}")
    if "response" in case:
        response = case["response"]
        print("  Input: hardcoded parsed VirusTotal response")
        print(f"  Resource: {response['resource_type']}")
        print(f"  Engine counts: {response['detection_stats']}")
        print(f"  Threat names: {response['threat_names']}")
    else:
        response = make_ai_response(case["active"])
        print("  Input: hardcoded parsed AI response")
        for indicator, evidence in case["active"].items():
            print(f"  {indicator} = True; evidence: {evidence}")
        if "remove_indicator" in case:
            del response["indicators"][case["remove_indicator"]]
            print(f"  {case['remove_indicator']} is missing.")
        elif not case["active"]:
            print("  All ten indicators are False.")
    print(f"  User action: {case['interaction']}")
    if case.get("user_exposure"):
        print(f"  Hardcoded Other exposure: {case['user_exposure']}")

    if "expected_error" in case:
        expected_error = case["expected_error"]
        print(f"  Expected: {expected_error.__name__}")
        try:
            logic.evaluate_text_risk(response, case["interaction"])
        except expected_error as error:
            print(f"  Actual: {type(error).__name__}")
        else:
            raise AssertionError("Invalid input was accepted.")
    else:
        if "response" in case:
            result = logic.evaluate_vt_risk(
                response, case["interaction"], case["user_exposure"]
            )
        else:
            result = logic.evaluate_text_risk(response, case["interaction"])
        mismatches = []
        for field, expected in case["expected"].items():
            actual = result.get(field)
            print(f"  {field}: expected={expected!r}; actual={actual!r}")
            if actual != expected:
                mismatches.append(field)
        if mismatches:
            raise AssertionError("Unexpected result for: " + ", ".join(mismatches))

    print(f"  Why: {case['explanation']}")


def run_tests():
    """Run all eighteen cases; return a nonzero exit code if any case fails."""
    cases = get_test_cases() + get_vt_test_cases()
    passed = 0
    print("LOGIC MANAGER: 18 OFFLINE TESTS")
    for number, case in enumerate(cases, 1):
        try:
            run_case(case, number)
        except Exception as error:
            print(f"  RESULT: FAIL ({type(error).__name__}: {error})")
        else:
            passed += 1
            print("  RESULT: PASS")

    print(f"\nTotal: {len(cases)} | Passed: {passed} | Failed: {len(cases) - passed}")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    sys.exit(run_tests())
