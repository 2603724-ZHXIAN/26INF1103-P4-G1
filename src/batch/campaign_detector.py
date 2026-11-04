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