"""ThreatEvidence domain entity.

Encapsulates individual indicators, telemetry flags, and excerpts observed
by analysis engines (Gemini, VirusTotal, Business Rules).
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional


class ThreatEvidence:
    """Represents a single verifiable piece of threat evidence.

    Demonstrates encapsulation by shielding internal attributes with protected
    naming conventions (_attribute) and providing validated access via properties.
    """

    VALID_SOURCES = {"gemini", "virustotal", "business_rule", "manual"}
    VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}

    def __init__(
        self,
        evidence_name: str,
        source: str = "business_rule",
        evidence_type: str = "indicator",
        evidence_value: Optional[str] = None,
        evidence_excerpt: Optional[str] = None,
        severity: str = "informational",
        evidence_id: Optional[int] = None,
        submission_id: Optional[int] = None,
        created_at: Optional[str] = None,
    ) -> None:
        self._evidence_id: Optional[int] = evidence_id
        self._submission_id: Optional[int] = submission_id
        self._source: str = ""
        self._evidence_type: str = str(evidence_type).strip() or "indicator"
        self._evidence_name: str = str(evidence_name).strip()
        self._evidence_value: Optional[str] = evidence_value
        self._evidence_excerpt: Optional[str] = evidence_excerpt
        self._severity: str = "informational"
        self._created_at: str = (
            created_at or datetime.now(timezone.utc).isoformat()
        )

        # Use setters to enforce validation rules
        self.source = source
        self.severity = severity

        if not self._evidence_name:
            raise ValueError("evidence_name cannot be empty.")

    # -------------------------------------------------------------------------
    # Properties (Encapsulation)
    # -------------------------------------------------------------------------

    @property
    def evidence_id(self) -> Optional[int]:
        """Return the database primary key ID if persisted."""
        return self._evidence_id

    @evidence_id.setter
    def evidence_id(self, value: int) -> None:
        if not isinstance(value, int) or value <= 0:
            raise ValueError("evidence_id must be a positive integer.")
        self._evidence_id = value

    @property
    def submission_id(self) -> Optional[int]:
        """Return the parent submission ID this evidence belongs to."""
        return self._submission_id

    @submission_id.setter
    def submission_id(self, value: int) -> None:
        if not isinstance(value, int) or value <= 0:
            raise ValueError("submission_id must be a positive integer.")
        self._submission_id = value

    @property
    def source(self) -> str:
        """Return the evidence provider source."""
        return self._source

    @source.setter
    def source(self, value: str) -> None:
        clean_val = str(value).strip().lower()
        if clean_val not in self.VALID_SOURCES:
            raise ValueError(
                f"Invalid source '{value}'. Allowed: {sorted(self.VALID_SOURCES)}"
            )
        self._source = clean_val

    @property
    def evidence_type(self) -> str:
        """Return the type classification of evidence."""
        return self._evidence_type

    @property
    def evidence_name(self) -> str:
        """Return the identifying name of the indicator or rule."""
        return self._evidence_name

    @property
    def evidence_value(self) -> Optional[str]:
        """Return the value or detection flag associated with this indicator."""
        return self._evidence_value

    @property
    def evidence_excerpt(self) -> Optional[str]:
        """Return the raw textual quote or telemetry excerpt supporting this evidence."""
        return self._evidence_excerpt

    @property
    def severity(self) -> str:
        """Return the severity level of this evidence."""
        return self._severity

    @severity.setter
    def severity(self, value: str) -> None:
        clean_val = str(value).strip().lower()
        if clean_val not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{value}'. Allowed: {sorted(self.VALID_SEVERITIES)}"
            )
        self._severity = clean_val

    @property
    def created_at(self) -> str:
        """Return the ISO 8601 creation timestamp."""
        return self._created_at

    # -------------------------------------------------------------------------
    # Domain & Helper Methods
    # -------------------------------------------------------------------------

    def is_concerning(self) -> bool:
        """Check if this evidence indicates moderate to critical risk."""
        return self._severity in {"medium", "high", "critical"}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evidence to a dictionary representation."""
        return {
            "evidence_id": self._evidence_id,
            "submission_id": self._submission_id,
            "evidence_source": self._source,
            "evidence_type": self._evidence_type,
            "evidence_name": self._evidence_name,
            "evidence_value": self._evidence_value,
            "evidence_excerpt": self._evidence_excerpt,
            "severity": self._severity,
            "created_at": self._created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatEvidence":
        """Reconstitute a ThreatEvidence object from a dictionary."""
        return cls(
            evidence_id=data.get("evidence_id"),
            submission_id=data.get("submission_id"),
            source=data.get("evidence_source", data.get("source", "business_rule")),
            evidence_type=data.get("evidence_type", "indicator"),
            evidence_name=data.get("evidence_name", data.get("name", "unknown")),
            evidence_value=data.get("evidence_value", data.get("value")),
            evidence_excerpt=data.get("evidence_excerpt", data.get("excerpt")),
            severity=data.get("severity", "informational"),
            created_at=data.get("created_at"),
        )

    def __repr__(self) -> str:
        return (
            f"ThreatEvidence(name={self._evidence_name!r}, "
            f"severity={self._severity!r}, source={self._source!r})"
        )

    def __str__(self) -> str:
        excerpt_display = (
            f' - "{self._evidence_excerpt}"' if self._evidence_excerpt else ""
        )
        return (
            f"[{self._severity.upper()}] {self._evidence_name} "
            f"({self._source}){excerpt_display}"
        )
