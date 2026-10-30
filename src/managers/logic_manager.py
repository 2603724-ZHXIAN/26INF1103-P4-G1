"""Deterministic threat rules using domain models.

Stage 1: encapsulated rule configuration and evidence validation.
No API, database, file or presentation operations belong in this class.
"""

from ..models import Submission


class LogicManager:
    """Apply local business rules to validated analysis evidence."""

    def __init__(self):
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
