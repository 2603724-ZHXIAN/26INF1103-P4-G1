from difflib import SequenceMatcher


class CampaignDetector:
    """Detect potentially related emails using text similarity."""

    def __init__(self, similarity_threshold: float = 0.75) -> None:
        if not 0.0 <= similarity_threshold <= 1.0:
            raise ValueError("Similarity threshold must be between 0 and 1.")

        self._similarity_threshold = similarity_threshold

    @property
    def similarity_threshold(self) -> float:
        return self._similarity_threshold

    def calculate_similarity(self, text_a: str, text_b: str) -> float:
        """Return a similarity score between 0.0 and 1.0."""

        if not isinstance(text_a, str) or not isinstance(text_b, str):
            raise TypeError("Both email messages must be strings.")

        text_a = " ".join(text_a.casefold().split())
        text_b = " ".join(text_b.casefold().split())

        if not text_a or not text_b:
            return 0.0

        return SequenceMatcher(None, text_a, text_b).ratio()


    def group_similar_emails(self, email_records: list[dict]) -> list[dict]:
        """Group completed emails with similar wording."""

        groups = []

        for record in email_records:
            if record.get("processing_status") != "completed":
                continue

            email_text = record.get("input_value")

            if not isinstance(email_text, str) or not email_text.strip():
                continue

            matched_group = None

            for group in groups:
                representative = group["representative_text"]

                similarity = self.calculate_similarity(
                    email_text,
                    representative
                )

                if similarity >= self._similarity_threshold:
                    matched_group = group
                    break

            if matched_group is None:
                groups.append({
                    "representative_text": email_text,
                    "submission_ids": [record.get("submission_id")],
                    "count": 1
                })
            else:
                matched_group["submission_ids"].append(
                    record.get("submission_id")
                )
                matched_group["count"] += 1

        return groups