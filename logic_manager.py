"""
logic_manager.py

Applies deterministic cybersecurity business rules to Gemini-enriched
text analysis.

Gemini extracts warning indicators and educational information.
This module determines message risk, user exposure, overall risk,
flags and routing outcomes.

"""


KNOWN_INDICATORS = {
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
}

DIRECT_HARM_INDICATORS = {
    "credential_request",
    "payment_request",
    "otp_request",
    "download_request"
}

MODERATE_INDICATORS = {
    "personal_information_request",
    "suspicious_link"
}

PERSUASION_INDICATORS = {
    "urgency_pressure",
    "authority_impersonation",
    "threatening_language",
    "reward_or_prize"
}

INTERACTION_LEVELS = {
    "viewed_only": "low",
    "clicked_link": "medium",
    "entered_information": "high",
    "opened_or_downloaded_file": "high",
    "made_payment_or_shared_banking_details": "high"
}

HIGH_EXPOSURE_FIELDS = {
    "entered_credentials",
    "shared_personal_information",
    "downloaded_or_opened_file",
    "shared_otp",
    "made_payment",
    "shared_banking_details",
    "installed_software",
    "granted_remote_access"
}

MEDIUM_EXPOSURE_FIELDS = {
    "clicked_or_opened_link"
}

CRITICAL_EXPOSURE_FIELDS = {
    "shared_otp",
    "made_payment",
    "shared_banking_details",
    "installed_software",
    "granted_remote_access"
}

OVERALL_RISK_MATRIX = {
    ("low", "low"): "low",
    ("low", "medium"): "medium",
    ("low", "high"): "high",
    ("medium", "low"): "medium",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "high"
}


def validate_indicator(indicator_data):
    """Return whether one Gemini indicator has a valid structure."""
    if not isinstance(indicator_data, dict):
        return False

    present = indicator_data.get("present")
    evidence = indicator_data.get("evidence")

    if not isinstance(present, bool):
        return False

    if not isinstance(evidence, str):
        return False

    if present and not evidence.strip():
        return False

    return True


def get_active_indicators(indicators):
    """Return valid indicators that Gemini marked as present."""
    active_indicators = set()
    invalid_indicators = []

    if not isinstance(indicators, dict):
        return active_indicators, [
            "The indicators field was not a valid object."
        ]

    for indicator_name in KNOWN_INDICATORS:
        indicator_data = indicators.get(indicator_name)

        if not validate_indicator(indicator_data):
            invalid_indicators.append(indicator_name)
            continue

        if indicator_data["present"] is True:
            active_indicators.add(indicator_name)

    return active_indicators, invalid_indicators


def get_indicator_evidence(indicators, indicator_names):
    """Return evidence for the requested active indicators."""
    evidence_items = []

    for indicator_name in sorted(indicator_names):
        indicator_data = indicators.get(indicator_name, {})
        evidence = indicator_data.get("evidence", "").strip()

        evidence_items.append(
            {
                "indicator": indicator_name,
                "evidence": evidence
            }
        )

    return evidence_items


def build_combination_rules():
    """Return the controlled multi-condition business rules."""
    return [
        {
            "rule_id": "credential_phishing_rule",
            "required_indicators": {
                "credential_request",
                "suspicious_link"
            },
            "risk_level": "high",
            "flag": "possible_credential_phishing",
            "reason": (
                "The message requests account credentials through "
                "a suspicious link."
            )
        },
        {
            "rule_id": "account_takeover_rule",
            "required_indicators": {
                "otp_request",
                "authority_impersonation"
            },
            "risk_level": "high",
            "flag": "possible_account_takeover",
            "reason": (
                "A sender claiming to represent an authority or "
                "organisation is requesting an OTP."
            )
        },
        {
            "rule_id": "financial_fraud_rule",
            "required_indicators": {
                "payment_request",
                "authority_impersonation"
            },
            "risk_level": "high",
            "flag": "possible_financial_fraud",
            "reason": (
                "A sender claiming to represent an authority or "
                "organisation is requesting payment."
            )
        },
        {
            "rule_id": "malware_delivery_rule",
            "required_indicators": {
                "download_request",
                "suspicious_link"
            },
            "risk_level": "high",
            "flag": "possible_malware_delivery",
            "reason": (
                "The message directs the recipient to download "
                "content through a suspicious link."
            )
        },
        {
            "rule_id": "prize_scam_rule",
            "required_indicators": {
                "reward_or_prize",
                "payment_request"
            },
            "risk_level": "high",
            "flag": "possible_prize_or_advance_fee_scam",
            "reason": (
                "The message promises a reward while requesting "
                "payment."
            )
        },
        {
            "rule_id": "personal_data_phishing_rule",
            "required_indicators": {
                "personal_information_request",
                "suspicious_link"
            },
            "risk_level": "high",
            "flag": "possible_personal_data_phishing",
            "reason": (
                "The message requests personal information through "
                "a suspicious link."
            )
        },
        {
            "rule_id": "pressure_impersonation_rule",
            "required_indicators": {
                "authority_impersonation",
                "urgency_pressure"
            },
            "risk_level": "medium",
            "flag": "possible_social_engineering",
            "reason": (
                "The message combines authority impersonation with "
                "pressure to act quickly."
            )
        },
        {
            "rule_id": "coercion_rule",
            "required_indicators": {
                "threatening_language",
                "urgency_pressure"
            },
            "risk_level": "medium",
            "flag": "possible_coercive_scam",
            "reason": (
                "The message uses threats together with urgency to "
                "pressure the recipient."
            )
        }
    ]


def match_combination_rules(active_indicators):
    """Return all business rules matched by active indicators."""
    matched_rules = []

    for rule in build_combination_rules():
        required = rule["required_indicators"]

        if required.issubset(active_indicators):
            matched_rules.append(
                {
                    "rule_id": rule["rule_id"],
                    "risk_level": rule["risk_level"],
                    "flag": rule["flag"],
                    "reason": rule["reason"],
                    "matched_indicators": sorted(required)
                }
            )

    return matched_rules


def get_highest_rule_level(matched_rules):
    """Return the highest risk level among matched rules."""
    levels = {
        rule["risk_level"]
        for rule in matched_rules
    }

    if "high" in levels:
        return "high"

    if "medium" in levels:
        return "medium"

    return None


def validate_other_warning_signs(gemini_result):
    """Return valid warning signs outside the controlled indicators."""
    warning_signs = gemini_result.get(
        "other_warning_signs",
        []
    )

    if not isinstance(warning_signs, list):
        return []

    valid_warning_signs = []

    for warning_sign in warning_signs:
        if not isinstance(warning_sign, dict):
            continue

        name = warning_sign.get("name")
        evidence = warning_sign.get("evidence")
        explanation = warning_sign.get("explanation")

        if not isinstance(name, str) or not name.strip():
            continue

        if not isinstance(evidence, str) or not evidence.strip():
            continue

        if not isinstance(explanation, str):
            explanation = ""

        valid_warning_signs.append(
            {
                "name": name.strip(),
                "evidence": evidence.strip(),
                "explanation": explanation.strip()
            }
        )

    return valid_warning_signs


def determine_fallback_message_risk(
    active_indicators,
    unknown_warning_signs
):
    """Determine message risk when no combination rule matches."""
    if active_indicators & DIRECT_HARM_INDICATORS:
        return {
            "level": "high",
            "flag": "direct_harm_request",
            "reason": (
                "The message requests an action that could affect "
                "the recipient's account, money or device."
            )
        }

    if active_indicators & MODERATE_INDICATORS:
        return {
            "level": "medium",
            "flag": "suspicious_request",
            "reason": (
                "The message requests personal information or "
                "directs the recipient to an unverified location."
            )
        }

    persuasion_matches = (
        active_indicators & PERSUASION_INDICATORS
    )

    if len(persuasion_matches) >= 2:
        return {
            "level": "medium",
            "flag": "multiple_persuasion_tactics",
            "reason": (
                "The message combines multiple persuasion or "
                "pressure techniques."
            )
        }

    if persuasion_matches:
        return {
            "level": "low",
            "flag": "warning_sign_detected",
            "reason": (
                "The message contains a warning sign, but no "
                "direct harmful request was detected."
            )
        }

    if unknown_warning_signs:
        return {
            "level": "medium",
            "flag": "unrecognised_warning_pattern",
            "reason": (
                "The message contains warning signs outside the "
                "current controlled rule set."
            )
        }

    return {
        "level": "low",
        "flag": None,
        "reason": (
            "No validated warning indicators were detected. "
            "This does not guarantee that the message is safe."
        )
    }


def determine_message_risk(
    gemini_result,
    active_indicators
):
    """Determine message risk using controlled business rules."""
    matched_rules = match_combination_rules(
        active_indicators
    )

    unknown_warning_signs = (
        validate_other_warning_signs(gemini_result)
    )

    rule_level = get_highest_rule_level(matched_rules)

    if rule_level:
        flags = [
            rule["flag"]
            for rule in matched_rules
        ]

        reasons = [
            rule["reason"]
            for rule in matched_rules
        ]

        if unknown_warning_signs:
            flags.append("unrecognised_warning_pattern")
            reasons.append(
                "Additional warning signs outside the controlled "
                "rule set were also detected."
            )

        return {
            "level": rule_level,
            "flags": flags,
            "reasons": reasons,
            "matched_rules": matched_rules,
            "unknown_warning_signs": unknown_warning_signs
        }

    fallback = determine_fallback_message_risk(
        active_indicators,
        unknown_warning_signs
    )

    flags = []

    if fallback["flag"]:
        flags.append(fallback["flag"])

    return {
        "level": fallback["level"],
        "flags": flags,
        "reasons": [fallback["reason"]],
        "matched_rules": [],
        "unknown_warning_signs": unknown_warning_signs
    }


def validate_user_exposure(user_exposure):
    """Return a safe user-exposure dictionary."""
    if not isinstance(user_exposure, dict):
        return {}

    validated_exposure = {}

    exposure_fields = (
        HIGH_EXPOSURE_FIELDS
        | MEDIUM_EXPOSURE_FIELDS
    )

    for field_name in exposure_fields:
        value = user_exposure.get(field_name, False)
        validated_exposure[field_name] = value is True

    return validated_exposure


def determine_other_exposure(user_exposure):
    """Determine exposure from a custom Other description."""
    validated_exposure = validate_user_exposure(
        user_exposure
    )

    matched_exposures = [
        field_name
        for field_name in sorted(HIGH_EXPOSURE_FIELDS)
        if validated_exposure.get(field_name) is True
    ]

    if matched_exposures:
        return {
            "level": "high",
            "matched_exposures": matched_exposures,
            "reason": (
                "The custom description indicates that the user "
                "shared sensitive information or exposed an "
                "account, payment method or device."
            )
        }

    matched_exposures = [
        field_name
        for field_name in sorted(MEDIUM_EXPOSURE_FIELDS)
        if validated_exposure.get(field_name) is True
    ]

    if matched_exposures:
        return {
            "level": "medium",
            "matched_exposures": matched_exposures,
            "reason": (
                "The custom description indicates that the user "
                "clicked or opened a link."
            )
        }

    return {
        "level": "low",
        "matched_exposures": [],
        "reason": (
            "The custom description does not indicate a known "
            "sensitive action."
        )
    }


def determine_user_exposure(
    interaction_type,
    user_exposure
):
    """Determine exposure from the authoritative user selection."""
    if interaction_type == "other":
        return determine_other_exposure(user_exposure)

    level = INTERACTION_LEVELS.get(interaction_type)

    if level is None:
        return {
            "level": "unknown",
            "matched_exposures": [],
            "reason": "The interaction type was not recognised."
        }

    descriptions = {
        "viewed_only": (
            "The user viewed the message without taking another "
            "reported action."
        ),
        "clicked_link": (
            "The user clicked a link but did not report entering "
            "information."
        ),
        "entered_information": (
            "The user entered personal or login information."
        ),
        "opened_or_downloaded_file": (
            "The user opened or downloaded a file."
        ),
        "made_payment_or_shared_banking_details": (
            "The user made a payment or shared banking details."
        )
    }

    return {
        "level": level,
        "matched_exposures": [interaction_type],
        "reason": descriptions[interaction_type]
    }


def determine_overall_risk(
    message_level,
    exposure_level,
    active_indicators
):
    """Combine message risk, evidence and user exposure."""
    if not active_indicators and message_level == "low":
        return "low"

    if exposure_level == "unknown":
        return "medium"

    return OVERALL_RISK_MATRIX.get(
        (message_level, exposure_level),
        "medium"
    )


def has_critical_exposure(
    interaction_type,
    user_exposure
):
    """Return whether the user performed a critical action."""
    if (
        interaction_type
        == "made_payment_or_shared_banking_details"
    ):
        return True

    if interaction_type != "other":
        return False

    validated_exposure = validate_user_exposure(
        user_exposure
    )

    return any(
        validated_exposure.get(field_name) is True
        for field_name in CRITICAL_EXPOSURE_FIELDS
    )


def determine_route(
    overall_risk,
    interaction_type,
    user_exposure,
    unknown_warning_signs
):
    """Decide the response route and priority."""
    validated_exposure = validate_user_exposure(
        user_exposure
    )

    financial_exposure = (
        interaction_type
        == "made_payment_or_shared_banking_details"
        or (
            interaction_type == "other"
            and (
                validated_exposure.get("shared_otp") is True
                or validated_exposure.get("made_payment") is True
                or validated_exposure.get(
                    "shared_banking_details"
                ) is True
            )
        )
    )

    device_exposure = (
        interaction_type == "opened_or_downloaded_file"
        or (
            interaction_type == "other"
            and (
                validated_exposure.get(
                    "downloaded_or_opened_file"
                ) is True
                or validated_exposure.get(
                    "installed_software"
                ) is True
                or validated_exposure.get(
                    "granted_remote_access"
                ) is True
            )
        )
    )

    account_exposure = (
        interaction_type == "entered_information"
        or (
            interaction_type == "other"
            and (
                validated_exposure.get(
                    "entered_credentials"
                ) is True
                or validated_exposure.get(
                    "shared_personal_information"
                ) is True
            )
        )
    )

    if financial_exposure:
        return {
            "decision": "flag",
            "route": "urgent_financial_response",
            "priority": "urgent",
            "recommended_action": (
                "Contact the bank or affected organisation "
                "immediately using an official channel."
            )
        }

    if device_exposure:
        return {
            "decision": "flag",
            "route": "device_security_response",
            "priority": "high",
            "recommended_action": (
                "Stop using the suspicious file or software and "
                "perform an approved security scan."
            )
        }

    if account_exposure:
        return {
            "decision": "flag",
            "route": "account_security_response",
            "priority": "high",
            "recommended_action": (
                "Change affected credentials through the official "
                "website and enable multi-factor authentication."
            )
        }

    if unknown_warning_signs and overall_risk != "high":
        return {
            "decision": "review",
            "route": "unrecognised_pattern_review",
            "priority": "medium",
            "recommended_action": (
                "Verify the message through an official channel "
                "because it contains an unfamiliar warning pattern."
            )
        }

    if overall_risk == "high":
        return {
            "decision": "flag",
            "route": "high_risk_guidance",
            "priority": "high",
            "recommended_action": (
                "Stop interacting with the message and verify the "
                "request through an official channel."
            )
        }

    if overall_risk == "medium":
        return {
            "decision": "review",
            "route": "verification_guidance",
            "priority": "medium",
            "recommended_action": (
                "Verify the sender through an official website, "
                "application or telephone number."
            )
        }

    return {
        "decision": "accept_with_caution",
        "route": "general_safety_education",
        "priority": "low",
        "recommended_action": (
            "Remain cautious and do not share sensitive information "
            "with unverified senders."
        )
    }

def determine_scam_outcome(
    gemini_result,
    message_result
):
    """Determine whether sufficient evidence supports a scam outcome."""
    classification = gemini_result.get(
        "message_classification",
        "uncertain"
    )

    matched_rules = message_result.get("matched_rules", [])
    message_level = message_result.get("level", "low")

    has_high_rule = any(
        rule.get("risk_level") == "high"
        for rule in matched_rules
    )

    if has_high_rule:
        return True

    if (
        classification == "scam"
        and message_level in {"medium", "high"}
    ):
        return True

    return False


def evaluate_text_risk(gemini_result, interaction_type):
    """Apply all text-analysis business rules."""
    if not isinstance(gemini_result, dict):
        raise ValueError(
            "Gemini analysis must be a dictionary."
        )

    if "error" in gemini_result:
        raise ValueError(
            "Cannot process an unsuccessful Gemini response."
        )

    indicators = gemini_result.get("indicators", {})
    user_exposure = gemini_result.get(
        "user_exposure",
        {}
    )

    active_indicators, invalid_indicators = (
        get_active_indicators(indicators)
    )

    message_result = determine_message_risk(
        gemini_result,
        active_indicators
    )

    exposure_result = determine_user_exposure(
        interaction_type,
        user_exposure
    )

    overall_risk = determine_overall_risk(
        message_result["level"],
        exposure_result["level"],
        active_indicators
    )

    if (
        active_indicators
        and has_critical_exposure(
            interaction_type,
            user_exposure
        )
    ):
        overall_risk = "high"

    route_result = determine_route(
        overall_risk,
        interaction_type,
        user_exposure,
        message_result["unknown_warning_signs"]
    )

    evidence = get_indicator_evidence(
        indicators,
        active_indicators
    )

    is_scam = determine_scam_outcome(
        gemini_result,
        message_result
    )

    risk_reasons = (
        message_result["reasons"]
        + [exposure_result["reason"]]
    )

    return {
        "is_scam": is_scam,
        "risk_score": None,
        "risk_category": overall_risk,
        "message_risk": message_result["level"],
        "exposure_level": exposure_result["level"],
        "overall_risk": overall_risk,
        "decision": route_result["decision"],
        "route": route_result["route"],
        "priority": route_result["priority"],
        "recommended_action": route_result[
            "recommended_action"
        ],
        "flags": message_result["flags"],
        "active_indicators": sorted(active_indicators),
        "indicator_evidence": evidence,
        "matched_rules": message_result["matched_rules"],
        "unknown_warning_signs": message_result[
            "unknown_warning_signs"
        ],
        "invalid_indicators": invalid_indicators,
        "risk_reasons": risk_reasons,
        "message_reasons": message_result["reasons"],
        "exposure_reason": exposure_result["reason"],
        "matched_exposures": exposure_result[
            "matched_exposures"
        ]
    }