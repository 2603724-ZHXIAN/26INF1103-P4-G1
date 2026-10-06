"""Six offline tests of logic_manager using hardcoded AI responses.

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


def run_case(case, number):
    """Call the actual evaluator, print results and verify expectations."""
    response = make_ai_response(case["active"])
    if "remove_indicator" in case:
        del response["indicators"][case["remove_indicator"]]

    print(f"\nTEST {number}: {case['name']}")
    for indicator, evidence in case["active"].items():
        print(f"  Input: {indicator} = True; evidence: {evidence}")
    if "remove_indicator" in case:
        print(f"  Input: {case['remove_indicator']} is missing.")
    elif not case["active"]:
        print("  Input: all ten indicators are False.")
    print(f"  User action: {case['interaction']}")

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
    """Run all six cases; return a nonzero exit code if any case fails."""
    cases = get_test_cases()
    passed = 0
    print("LOGIC MANAGER: SIX OFFLINE TESTS")
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
