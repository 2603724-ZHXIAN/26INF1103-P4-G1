"""Deterministic threat rules using domain models.

Encapsulated rules, evidence validation, text rules and exposure routing.
No API, database, file or presentation operations belong in this class.
"""

from ..models import AssessmentResult, Submission


class LogicManager:
    """Apply local business rules to validated analysis evidence."""

    def __init__(self):
        self._technical_thresholds = {
            "high_malicious": 5, "high_ratio": 10, "high_negative_reputation": -20,
            "medium_malicious": 1, "medium_suspicious": 2, "medium_ratio": 3,
        }
        # Each instance owns its rule collections; no shared mutable tables.
        self._known_indicators = {'authority_impersonation',
         'credential_request',
         'download_request',
         'otp_request',
         'payment_request',
         'personal_information_request',
         'reward_or_prize',
         'suspicious_link',
         'threatening_language',
         'urgency_pressure'}
        self._direct_harm_indicators = {'payment_request', 'otp_request', 'download_request', 'credential_request'}
        self._moderate_indicators = {'personal_information_request', 'suspicious_link'}
        self._persuasion_indicators = {'authority_impersonation',
         'reward_or_prize',
         'threatening_language',
         'urgency_pressure'}
        self._interaction_levels = {'clicked_link': 'medium',
         'entered_information': 'high',
         'made_payment_or_shared_banking_details': 'high',
         'opened_or_downloaded_file': 'high',
         'viewed_only': 'low'}
        self._high_exposure_fields = {'downloaded_or_opened_file',
         'entered_credentials',
         'granted_remote_access',
         'installed_software',
         'made_payment',
         'shared_banking_details',
         'shared_otp',
         'shared_personal_information'}
        self._medium_exposure_fields = {'clicked_or_opened_link'}
        self._critical_exposure_fields = {'granted_remote_access',
         'installed_software',
         'made_payment',
         'shared_banking_details',
         'shared_otp'}
        self._risk_matrix = {('high', 'high'): 'high',
         ('high', 'low'): 'high',
         ('high', 'medium'): 'high',
         ('low', 'high'): 'low',
         ('low', 'low'): 'low',
         ('low', 'medium'): 'low',
         ('medium', 'high'): 'high',
         ('medium', 'low'): 'medium',
         ('medium', 'medium'): 'medium'}

    @staticmethod
    def _validate_submission(submission: Submission, allowed_types) -> None:
        """Reject the wrong domain object or pipeline before evaluating it."""
        if not isinstance(submission, Submission):
            raise TypeError("submission must be a Submission object.")
        if submission.input_type not in allowed_types:
            raise ValueError("The submission type does not match this analysis pipeline.")

    @staticmethod
    def _validate_indicator(indicator_data) -> bool:
        """An active indicator must have boolean presence and quoted evidence."""
        if not isinstance(indicator_data, dict):
            return False
        present = indicator_data.get("present")
        evidence = indicator_data.get("evidence")
        return (
            isinstance(present, bool)
            and isinstance(evidence, str)
            and (not present or bool(evidence.strip()))
        )

    def _get_active_indicators(self, indicators) -> set[str]:
        """Require complete evidence rather than defaulting missing signs to safe."""
        if not isinstance(indicators, dict):
            raise ValueError("The indicators field must be a dictionary.")
        invalid = sorted(
            name for name in self._known_indicators
            if not self._validate_indicator(indicators.get(name))
        )
        if invalid:
            raise ValueError("Missing or invalid warning indicators: " + ", ".join(invalid))
        return {
            name for name in self._known_indicators
            if indicators[name]["present"]
        }

    def _build_combination_rules(self):
        """Return the controlled multi-condition business rules."""
        return [{'rule_id': 'credential_phishing_rule', 'required_indicators': {'credential_request', 'suspicious_link'}, 'risk_level': 'high', 'flag': 'possible_credential_phishing', 'reason': 'The message requests account credentials through a suspicious link.'}, {'rule_id': 'account_takeover_rule', 'required_indicators': {'otp_request', 'authority_impersonation'}, 'risk_level': 'high', 'flag': 'possible_account_takeover', 'reason': 'A sender claiming to represent an authority or organisation is requesting an OTP.'}, {'rule_id': 'financial_fraud_rule', 'required_indicators': {'payment_request', 'authority_impersonation'}, 'risk_level': 'high', 'flag': 'possible_financial_fraud', 'reason': 'A sender claiming to represent an authority or organisation is requesting payment.'}, {'rule_id': 'malware_delivery_rule', 'required_indicators': {'download_request', 'suspicious_link'}, 'risk_level': 'high', 'flag': 'possible_malware_delivery', 'reason': 'The message directs the recipient to download content through a suspicious link.'}, {'rule_id': 'prize_scam_rule', 'required_indicators': {'reward_or_prize', 'payment_request'}, 'risk_level': 'high', 'flag': 'possible_prize_or_advance_fee_scam', 'reason': 'The message promises a reward while requesting payment.'}, {'rule_id': 'personal_data_phishing_rule', 'required_indicators': {'personal_information_request', 'suspicious_link'}, 'risk_level': 'high', 'flag': 'possible_personal_data_phishing', 'reason': 'The message requests personal information through a suspicious link.'}, {'rule_id': 'pressure_impersonation_rule', 'required_indicators': {'authority_impersonation', 'urgency_pressure'}, 'risk_level': 'medium', 'flag': 'possible_social_engineering', 'reason': 'The message combines authority impersonation with pressure to act quickly.'}, {'rule_id': 'coercion_rule', 'required_indicators': {'threatening_language', 'urgency_pressure'}, 'risk_level': 'medium', 'flag': 'possible_coercive_scam', 'reason': 'The message uses threats together with urgency to pressure the recipient.'}]

    def _match_combination_rules(self, active_indicators):
        """Return all business rules matched by active indicators."""
        matched_rules = []
        for rule in self._build_combination_rules():
            required = rule['required_indicators']
            if required.issubset(active_indicators):
                matched_rules.append({'rule_id': rule['rule_id'], 'risk_level': rule['risk_level'], 'flag': rule['flag'], 'reason': rule['reason'], 'matched_indicators': sorted(required)})
        return matched_rules

    def _get_highest_rule_level(self, matched_rules):
        """Return the highest risk level among matched rules."""
        levels = {rule['risk_level'] for rule in matched_rules}
        if 'high' in levels:
            return 'high'
        if 'medium' in levels:
            return 'medium'
        return None

    def _validate_other_warning_signs(self, gemini_result):
        """Return valid warning signs outside the controlled indicators."""
        warning_signs = gemini_result.get('other_warning_signs', [])
        if not isinstance(warning_signs, list):
            return []
        valid_warning_signs = []
        for warning_sign in warning_signs:
            if not isinstance(warning_sign, dict):
                continue
            name = warning_sign.get('name')
            evidence = warning_sign.get('evidence')
            explanation = warning_sign.get('explanation')
            if not isinstance(name, str) or not name.strip():
                continue
            if not isinstance(evidence, str) or not evidence.strip():
                continue
            if not isinstance(explanation, str):
                explanation = ''
            valid_warning_signs.append({'name': name.strip(), 'evidence': evidence.strip(), 'explanation': explanation.strip()})
        return valid_warning_signs

    def _determine_fallback_message_risk(self, active_indicators, unknown_warning_signs):
        """Determine message risk when no combination rule matches."""
        if active_indicators & self._direct_harm_indicators:
            return {'level': 'high', 'flag': 'direct_harm_request', 'reason': "The message requests an action that could affect the recipient's account, money or device."}
        if active_indicators & self._moderate_indicators:
            return {'level': 'medium', 'flag': 'suspicious_request', 'reason': 'The message requests personal information or directs the recipient to an unverified location.'}
        persuasion_matches = active_indicators & self._persuasion_indicators
        if len(persuasion_matches) >= 2:
            return {'level': 'medium', 'flag': 'multiple_persuasion_tactics', 'reason': 'The message combines multiple persuasion or pressure techniques.'}
        if persuasion_matches:
            return {'level': 'low', 'flag': 'warning_sign_detected', 'reason': 'The message contains a warning sign, but no direct harmful request was detected.'}
        if unknown_warning_signs:
            return {'level': 'medium', 'flag': 'unrecognised_warning_pattern', 'reason': 'The message contains warning signs outside the current controlled rule set.'}
        return {'level': 'low', 'flag': None, 'reason': 'No validated warning indicators were detected. This does not guarantee that the message is safe.'}

    def _determine_message_risk(self, gemini_result, active_indicators):
        """Determine message risk using controlled business rules."""
        matched_rules = self._match_combination_rules(active_indicators)
        unknown_warning_signs = self._validate_other_warning_signs(gemini_result)
        rule_level = self._get_highest_rule_level(matched_rules)
        if rule_level:
            flags = [rule['flag'] for rule in matched_rules]
            reasons = [rule['reason'] for rule in matched_rules]
            if unknown_warning_signs:
                flags.append('unrecognised_warning_pattern')
                reasons.append('Additional warning signs outside the controlled rule set were also detected.')
            return {'level': rule_level, 'flags': flags, 'reasons': reasons, 'matched_rules': matched_rules, 'unknown_warning_signs': unknown_warning_signs}
        fallback = self._determine_fallback_message_risk(active_indicators, unknown_warning_signs)
        flags = []
        if fallback['flag']:
            flags.append(fallback['flag'])
        return {'level': fallback['level'], 'flags': flags, 'reasons': [fallback['reason']], 'matched_rules': [], 'unknown_warning_signs': unknown_warning_signs}

    def _validate_user_exposure(self, user_exposure):
        """Return a safe user-exposure dictionary."""
        if not isinstance(user_exposure, dict):
            return {}
        validated_exposure = {}
        exposure_fields = self._high_exposure_fields | self._medium_exposure_fields
        for field_name in exposure_fields:
            value = user_exposure.get(field_name, False)
            validated_exposure[field_name] = value is True
        return validated_exposure

    def _determine_other_exposure(self, user_exposure):
        """Determine exposure from a custom Other description."""
        validated_exposure = self._validate_user_exposure(user_exposure)
        matched_exposures = [field_name for field_name in sorted(self._high_exposure_fields) if validated_exposure.get(field_name) is True]
        if matched_exposures:
            return {'level': 'high', 'matched_exposures': matched_exposures, 'reason': 'The custom description indicates that the user shared sensitive information or exposed an account, payment method or device.'}
        matched_exposures = [field_name for field_name in sorted(self._medium_exposure_fields) if validated_exposure.get(field_name) is True]
        if matched_exposures:
            return {'level': 'medium', 'matched_exposures': matched_exposures, 'reason': 'The custom description indicates that the user clicked or opened a link.'}
        return {'level': 'low', 'matched_exposures': [], 'reason': 'The custom description does not indicate a known sensitive action.'}

    def _determine_user_exposure(self, interaction_type, user_exposure):
        """Determine exposure from the authoritative user selection."""
        if interaction_type == 'other':
            if user_exposure is None:
                return {'level': 'unknown', 'matched_exposures': [], 'reason': 'The custom interaction could not be interpreted reliably.'}
            return self._determine_other_exposure(user_exposure)
        level = self._interaction_levels.get(interaction_type)
        if level is None:
            return {'level': 'unknown', 'matched_exposures': [], 'reason': 'The interaction type was not recognised.'}
        descriptions = {'viewed_only': 'The user viewed the item without taking another reported action.', 'clicked_link': 'The user clicked a link but did not report entering information.', 'entered_information': 'The user entered personal or login information.', 'opened_or_downloaded_file': 'The user opened or downloaded a file.', 'made_payment_or_shared_banking_details': 'The user made a payment or shared banking details.'}
        return {'level': level, 'matched_exposures': [interaction_type], 'reason': descriptions[interaction_type]}

    def _determine_overall_risk(self, message_level, exposure_level):
        """Combine technical/message risk and user exposure."""
        if exposure_level == 'unknown':
            if message_level in {'low', 'medium', 'high'}:
                return message_level
            return 'medium'
        return self._risk_matrix.get((message_level, exposure_level), 'medium')

    def _has_critical_exposure(self, interaction_type, user_exposure):
        """Return whether the user performed a critical action."""
        if interaction_type == 'made_payment_or_shared_banking_details':
            return True
        if interaction_type != 'other':
            return False
        validated_exposure = self._validate_user_exposure(user_exposure)
        return any((validated_exposure.get(field_name) is True for field_name in self._critical_exposure_fields))

    def _determine_route(self, overall_risk, interaction_type, user_exposure, unknown_warning_signs, source_risk_level):
        """Decide the response route and priority."""
        validated_exposure = self._validate_user_exposure(user_exposure)
        financial_exposure = interaction_type == 'made_payment_or_shared_banking_details' or (interaction_type == 'other' and (validated_exposure.get('shared_otp') is True or validated_exposure.get('made_payment') is True or validated_exposure.get('shared_banking_details') is True))
        device_exposure = interaction_type == 'opened_or_downloaded_file' or (interaction_type == 'other' and (validated_exposure.get('downloaded_or_opened_file') is True or validated_exposure.get('installed_software') is True or validated_exposure.get('granted_remote_access') is True))
        account_exposure = interaction_type == 'entered_information' or (interaction_type == 'other' and (validated_exposure.get('entered_credentials') is True or validated_exposure.get('shared_personal_information') is True))
        exposure_response_required = source_risk_level in {'medium', 'high'} or (overall_risk == 'high' and self._has_critical_exposure(interaction_type, user_exposure))
        if financial_exposure and exposure_response_required:
            return {'decision': 'flag', 'route': 'urgent_financial_response', 'priority': 'urgent', 'recommended_action': 'Contact the bank or affected organisation immediately using an official channel.'}
        if device_exposure and exposure_response_required:
            return {'decision': 'flag', 'route': 'device_security_response', 'priority': 'high', 'recommended_action': 'Stop using the suspicious file or software and perform an approved security scan.'}
        if account_exposure and exposure_response_required:
            return {'decision': 'flag', 'route': 'account_security_response', 'priority': 'high', 'recommended_action': 'Change affected credentials through the official website and enable multi-factor authentication.'}
        if unknown_warning_signs and overall_risk != 'high':
            return {'decision': 'review', 'route': 'unrecognised_pattern_review', 'priority': 'medium', 'recommended_action': 'Verify the message through an official channel because it contains an unfamiliar warning pattern.'}
        if overall_risk == 'high':
            return {'decision': 'flag', 'route': 'high_risk_guidance', 'priority': 'high', 'recommended_action': 'Stop interacting with the message and verify the request through an official channel.'}
        if overall_risk == 'medium':
            return {'decision': 'review', 'route': 'verification_guidance', 'priority': 'medium', 'recommended_action': 'Verify the sender through an official website, application or telephone number.'}
        return {'decision': 'accept_with_caution', 'route': 'general_safety_education', 'priority': 'low', 'recommended_action': 'Remain cautious and do not share sensitive information with unverified senders.'}

    def _get_indicator_evidence(self, indicators, indicator_names):
        """Return evidence for the requested active indicators."""
        evidence_items = []
        for indicator_name in sorted(indicator_names):
            indicator_data = indicators.get(indicator_name, {})
            evidence = indicator_data.get('evidence', '').strip()
            evidence_items.append({'indicator': indicator_name, 'evidence': evidence})
        return evidence_items

    def _determine_scam_outcome(self, gemini_result, message_result):
        """Determine whether sufficient evidence supports a scam outcome."""
        classification = gemini_result.get('message_classification', 'uncertain')
        matched_rules = message_result.get('matched_rules', [])
        message_level = message_result.get('level', 'low')
        has_high_rule = any((rule.get('risk_level') == 'high' for rule in matched_rules))
        if has_high_rule:
            return True
        if classification == 'scam' and message_level in {'medium', 'high'}:
            return True
        return False

    def _evaluate_text_risk(self, gemini_result, interaction_type):
        """Apply all text-analysis business rules."""
        if not isinstance(gemini_result, dict):
            raise ValueError('Gemini analysis must be a dictionary.')
        if 'error' in gemini_result:
            raise ValueError('Cannot process an unsuccessful Gemini response.')
        indicators = gemini_result.get('indicators', {})
        user_exposure = gemini_result.get('user_exposure')
        active_indicators = self._get_active_indicators(indicators)
        invalid_indicators = []
        if invalid_indicators:
            raise ValueError('The AI response contains missing or invalid warning indicators. A reliable risk assessment could not be completed. Please try again.')
        message_result = self._determine_message_risk(gemini_result, active_indicators)
        exposure_result = self._determine_user_exposure(interaction_type, user_exposure)
        overall_risk = self._determine_overall_risk(message_result['level'], exposure_result['level'])
        if active_indicators and self._has_critical_exposure(interaction_type, user_exposure):
            overall_risk = 'high'
        route_result = self._determine_route(overall_risk, interaction_type, user_exposure, message_result['unknown_warning_signs'], message_result['level'])
        evidence = self._get_indicator_evidence(indicators, active_indicators)
        is_scam = self._determine_scam_outcome(gemini_result, message_result)
        risk_reasons = message_result['reasons'] + [exposure_result['reason']]
        return {'is_scam': is_scam, 'risk_score': None, 'risk_category': overall_risk, 'message_risk': message_result['level'], 'exposure_level': exposure_result['level'], 'overall_risk': overall_risk, 'decision': route_result['decision'], 'route': route_result['route'], 'priority': route_result['priority'], 'recommended_action': route_result['recommended_action'], 'flags': message_result['flags'], 'active_indicators': sorted(active_indicators), 'indicator_evidence': evidence, 'matched_rules': message_result['matched_rules'], 'unknown_warning_signs': message_result['unknown_warning_signs'], 'invalid_indicators': invalid_indicators, 'risk_reasons': risk_reasons, 'message_reasons': message_result['reasons'], 'exposure_reason': exposure_result['reason'], 'matched_exposures': exposure_result['matched_exposures']}

    @staticmethod
    def _to_assessment(result: dict) -> AssessmentResult:
        """Adapt rule findings to the shared domain model without changing risk rules."""
        data = dict(result)
        if data["exposure_level"] == "unknown":
            # The shared model accepts only low/medium/high. Keep the explanation
            # explicit so medium is not mistaken for confirmed user activity.
            data["exposure_level"] = "medium"
            note = "Exposure is unconfirmed; medium is used as the model-compatible placeholder."
            data["exposure_reason"] += " " + note
            data["risk_reasons"] = list(data["risk_reasons"]) + [note]
        data["recovery_steps"] = [data["recommended_action"]]
        return AssessmentResult.from_dict(data)

    def evaluate_text_threat(self, submission: Submission, ai_data: dict) -> AssessmentResult:
        """Evaluate text locally and attach a result only after validation succeeds."""
        self._validate_submission(submission, {"text"})
        if not isinstance(ai_data, dict):
            raise ValueError("AI analysis must be a dictionary.")
        if submission.interaction_type == "other":
            exposure = ai_data.get("user_exposure")
            if exposure is not None:
                if not isinstance(exposure, dict):
                    raise ValueError("Interpreted exposure must be a dictionary or None.")
                for name in self._high_exposure_fields | self._medium_exposure_fields:
                    if name in exposure and not isinstance(exposure[name], bool):
                        raise ValueError("Interpreted exposure flags must be booleans.")
        result = self._evaluate_text_risk(ai_data, submission.interaction_type)
        assessment = self._to_assessment(result)
        submission.set_assessment(assessment)
        return assessment

    @staticmethod
    def _parse_integer(value, field: str) -> int:
        """Accept integers and integer strings, without truncating invalid data."""
        if type(value) is int:
            return value
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                pass
        raise ValueError(f"{field} must be an integer.")

    def _evaluate_technical_evidence(self, vt_data: dict) -> dict:
        """Validate parsed scanner evidence and calculate technical risk locally."""
        if not isinstance(vt_data, dict) or "error" in vt_data:
            raise ValueError("A successful parsed VirusTotal response is required.")
        stats = vt_data.get("detection_stats")
        if not isinstance(stats, dict):
            raise ValueError("VirusTotal detection statistics are missing.")
        counts = {}
        for name in ("malicious", "suspicious", "harmless", "undetected"):
            if name not in stats:
                raise ValueError(f"Missing VirusTotal engine count: {name}.")
            counts[name] = self._parse_integer(stats[name], name)
        counts["timeout"] = self._parse_integer(stats.get("timeout", 0), "timeout")
        if any(value < 0 for value in counts.values()):
            raise ValueError("VirusTotal detection counts cannot be negative.")
        reputation = self._parse_integer(vt_data.get("reputation", 0), "reputation")
        completed = sum(counts[name] for name in ("malicious", "suspicious", "harmless", "undetected"))
        if completed == 0:
            raise ValueError("No security engines completed their assessment.")
        ratio = (counts["malicious"] + counts["suspicious"]) / completed * 100
        thresholds = self._technical_thresholds
        if (counts["malicious"] >= thresholds["high_malicious"]
                or ratio >= thresholds["high_ratio"]
                or reputation <= thresholds["high_negative_reputation"]):
            risk = "high"
        elif (counts["malicious"] >= thresholds["medium_malicious"]
                or counts["suspicious"] >= thresholds["medium_suspicious"]
                or ratio >= thresholds["medium_ratio"] or reputation < 0):
            risk = "medium"
        else:
            risk = "low"
        labels = []
        for field in ("threat_names", "categories"):
            values = vt_data.get(field, [])
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise ValueError(f"{field} must be a list of strings.")
            labels.extend(item.strip() for item in values if item.strip())
        return {
            "technical_risk": risk,
            "detection_ratio": round(ratio, 2),
            "flags": sorted(set(labels)),
            "risk_reasons": [
                f"{counts['malicious']} engine(s) classified the item as malicious.",
                f"{counts['suspicious']} engine(s) classified the item as suspicious.",
                f"The detection ratio is {ratio:.2f}%.",
                f"The VirusTotal reputation value is {reputation}.",
            ],
        }
