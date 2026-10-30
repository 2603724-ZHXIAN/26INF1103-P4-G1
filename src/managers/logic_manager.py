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
