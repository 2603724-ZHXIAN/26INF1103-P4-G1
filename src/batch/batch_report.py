from collections import Counter
from src.batch.campaign_detector import CampaignDetector

class BatchReport:
    """Prepare statistics and rankings for an analysed email batch."""

    def __init__(
        self,
        batch_info: dict,
        email_records: list[dict],
        campaign_detector: CampaignDetector | None = None
    ) -> None:
        self._batch_info = batch_info.copy()
        self._email_records = [record.copy() for record in email_records]
        self._campaign_detector = (
            campaign_detector
            if campaign_detector is not None
            else CampaignDetector()
        )
        
    @property
    def batch_info(self) -> dict:
        return self._batch_info.copy()

    @property
    def email_records(self) -> list[dict]:
        return [record.copy() for record in self._email_records]

    def generate_summary(self) -> dict:
        """Return saved processing and risk statistics for this batch."""

        return {
            "batch_reference": self._batch_info.get("batch_reference"),
            "total_emails": self._batch_info.get("saved_email_count") or 0,
            "completed": self._batch_info.get("completed_count") or 0,
            "failed": self._batch_info.get("analysis_failed_count") or 0,
            "high_risk": self._batch_info.get("high_risk_count") or 0,
            "medium_risk": self._batch_info.get("medium_risk_count") or 0,
            "low_risk": self._batch_info.get("low_risk_count") or 0,
        }

    def get_risk_distribution(self) -> dict:
        """Calculate risk percentages among classified emails."""

        summary = self.generate_summary()

        high = summary["high_risk"]
        medium = summary["medium_risk"]
        low = summary["low_risk"]

        classified_total = high + medium + low

        if classified_total == 0:
            return {
                "high": 0.0,
                "medium": 0.0,
                "low": 0.0,
            }

        return {
            "high": round(high / classified_total * 100, 2),
            "medium": round(medium / classified_total * 100, 2),
            "low": round(low / classified_total * 100, 2),
        }

    def get_common_threats(self) -> list[dict]:
        """Count primary threat types in completed email analyses."""

        threat_types = []

        for record in self._email_records:
            if record.get("processing_status") != "completed":
                continue

            threat_type = record.get("primary_threat_type")

            if not isinstance(threat_type, str):
                continue

            threat_type = threat_type.strip().casefold()

            if not threat_type:
                continue

            threat_types.append(threat_type)

        counts = Counter(threat_types)

        return [
            {"threat_type": threat, "count": count}
            for threat, count in counts.most_common()
        ]

    def get_ranked_results(self) -> list[dict]:
        """Rank completed emails by risk category, highest first."""

        risk_priority = {
            "high": 3,
            "medium": 2,
            "low": 1,
        }

        ranked_records = []

        for record in self._email_records:
            if record.get("processing_status") != "completed":
                continue

            risk = record.get("overall_risk")

            if not isinstance(risk, str):
                continue

            risk = risk.strip().casefold()

            if risk not in risk_priority:
                continue

            ranked_records.append({
                "submission_id": record.get("submission_id"),
                "overall_risk": risk,
                "risk_score": record.get("risk_score"),
                "primary_threat_type": record.get("primary_threat_type"),
                "threat_summary": record.get("threat_summary"),
                "recommended_action": record.get("recommended_action"),
                "risk_reasons": record.get("risk_reasons") or [],
            })

        ranked_records.sort(
            key=lambda record: risk_priority[record["overall_risk"]],
            reverse=True,
        )

        return ranked_records


    def get_high_risk_results(self) -> list[dict]:
        """Return completed high-risk emails in their original order."""

        ranked_results = self.get_ranked_results()

        return [
            result
            for result in ranked_results
            if isinstance(result.get("overall_risk"), str)
            and result["overall_risk"].strip().casefold() == "high"
        ]

    def get_campaign_groups(self) -> list[dict]:
        """Return groups of emails with similar wording."""
        return self._campaign_detector.group_similar_emails(
            self._email_records
        )

    def get_campaign_patterns(self, group: dict) -> dict:
        """Return common threat patterns for a campaign group."""
        return self._campaign_detector.identify_common_patterns(group)