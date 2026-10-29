"""Submission domain entity (Aggregate Root).

Encapsulates user input, reported interaction exposure, cryptographic verification hash,
processing lifecycle state, and owns the composite lifecycle of ThreatEvidence and AssessmentResult.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .assessment import AssessmentResult
from .evidence import ThreatEvidence


class Submission:
    """Represents a user-submitted investigation request.

    Demonstrates:
    - Encapsulation: Internal state protected with _attributes and validated properties.
    - Composition: Owns the lifecycle of AssessmentResult and ThreatEvidence objects.
    """

    VALID_INPUT_TYPES = {"text", "url", "file"}
    VALID_STATUSES = {"pending", "processing", "completed", "failed"}
    VALID_INTERACTIONS = {
        "viewed_only",
        "clicked_link",
        "entered_information",
        "opened_or_downloaded_file",
        "made_payment_or_shared_banking_details",
        "other",
    }

    def __init__(
        self,
        input_type: str,
        input_value: str,
        interaction_type: str = "viewed_only",
        interaction_description: Optional[str] = None,
        input_hash: Optional[str] = None,
        file_path: Optional[str] = None,
        data_origin: str = "cli",
        dataset_batch: Optional[str] = None,
        processing_status: str = "pending",
        error_message: Optional[str] = None,
        submission_id: Optional[int] = None,
        created_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        assessment: Optional[AssessmentResult] = None,
        evidences: Optional[List[ThreatEvidence]] = None,
    ) -> None:
        self._submission_id: Optional[int] = submission_id
        self._input_type: str = ""
        self._input_value: str = str(input_value).strip()
        self._input_hash: str = ""
        self._file_path: Optional[str] = file_path
        self._interaction_type: str = "viewed_only"
        self._interaction_description: Optional[str] = interaction_description
        self._data_origin: str = str(data_origin).strip() or "cli"
        self._dataset_batch: Optional[str] = dataset_batch
        self._processing_status: str = "pending"
        self._error_message: Optional[str] = error_message
        self._created_at: str = (
            created_at or datetime.now(timezone.utc).isoformat()
        )
        self._completed_at: Optional[str] = completed_at

        # Composition: Submission manages these parts
        self._assessment: Optional[AssessmentResult] = None
        self._evidences: List[ThreatEvidence] = []

        # Enforce validation through property setters
        self.input_type = input_type
        self.interaction_type = interaction_type
        self.processing_status = processing_status

        if input_hash:
            self._input_hash = str(input_hash).strip()
        else:
            self._input_hash = self.generate_hash(self._input_value)

        if assessment:
            self.set_assessment(assessment)

        if evidences:
            for ev in evidences:
                self.add_evidence(ev)

    # -------------------------------------------------------------------------
    # Properties (Encapsulation)
    # -------------------------------------------------------------------------

    @property
    def submission_id(self) -> Optional[int]:
        return self._submission_id

    @submission_id.setter
    def submission_id(self, value: int) -> None:
        if not isinstance(value, int) or value <= 0:
            raise ValueError("submission_id must be a positive integer.")
        self._submission_id = value
        # Propagate ID to composed objects if present
        if self._assessment:
            self._assessment.submission_id = value
        for ev in self._evidences:
            ev.submission_id = value

    @property
    def input_type(self) -> str:
        return self._input_type

    @input_type.setter
    def input_type(self, value: str) -> None:
        clean_val = str(value).strip().lower()
        if clean_val not in self.VALID_INPUT_TYPES:
            raise ValueError(
                f"Invalid input_type '{value}'. Allowed: {sorted(self.VALID_INPUT_TYPES)}"
            )
        self._input_type = clean_val

    @property
    def input_value(self) -> str:
        return self._input_value

    @property
    def input_hash(self) -> str:
        return self._input_hash

    @property
    def file_path(self) -> Optional[str]:
        return self._file_path

    @file_path.setter
    def file_path(self, value: Optional[str]) -> None:
        self._file_path = str(value).strip() if value else None

    @property
    def interaction_type(self) -> str:
        return self._interaction_type

    @interaction_type.setter
    def interaction_type(self, value: str) -> None:
        clean_val = str(value).strip().lower()
        if clean_val not in self.VALID_INTERACTIONS:
            raise ValueError(
                f"Invalid interaction_type '{value}'. Allowed: {sorted(self.VALID_INTERACTIONS)}"
            )
        self._interaction_type = clean_val

    @property
    def interaction_description(self) -> Optional[str]:
        return self._interaction_description

    @interaction_description.setter
    def interaction_description(self, value: Optional[str]) -> None:
        self._interaction_description = str(value).strip() if value else None

    @property
    def data_origin(self) -> str:
        return self._data_origin

    @property
    def dataset_batch(self) -> Optional[str]:
        return self._dataset_batch

    @property
    def processing_status(self) -> str:
        return self._processing_status

    @processing_status.setter
    def processing_status(self, value: str) -> None:
        clean_val = str(value).strip().lower()
        if clean_val not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid processing_status '{value}'. Allowed: {sorted(self.VALID_STATUSES)}"
            )
        self._processing_status = clean_val

    @property
    def error_message(self) -> Optional[str]:
        return self._error_message

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def completed_at(self) -> Optional[str]:
        return self._completed_at

    @property
    def assessment(self) -> Optional[AssessmentResult]:
        """Access the composed assessment result."""
        return self._assessment

    @property
    def evidences(self) -> List[ThreatEvidence]:
        """Access a copy of the composed evidence collection."""
        return list(self._evidences)

    # -------------------------------------------------------------------------
    # Composition Methods
    # -------------------------------------------------------------------------

    def set_assessment(self, assessment: AssessmentResult) -> None:
        """Attach an assessment to this submission (Composition)."""
        if not isinstance(assessment, AssessmentResult):
            raise TypeError("assessment must be an instance of AssessmentResult.")
        if self._submission_id is not None:
            assessment.submission_id = self._submission_id
        self._assessment = assessment

    def add_evidence(self, evidence: ThreatEvidence) -> None:
        """Add a ThreatEvidence object to this submission (Composition)."""
        if not isinstance(evidence, ThreatEvidence):
            raise TypeError("evidence must be an instance of ThreatEvidence.")
        if self._submission_id is not None:
            evidence.submission_id = self._submission_id
        self._evidences.append(evidence)

    def create_evidence(
        self,
        name: str,
        source: str = "business_rule",
        evidence_type: str = "indicator",
        evidence_value: Optional[str] = None,
        excerpt: Optional[str] = None,
        severity: str = "informational",
    ) -> ThreatEvidence:
        """Factory method demonstrating tight composition ownership."""
        ev = ThreatEvidence(
            evidence_name=name,
            source=source,
            evidence_type=evidence_type,
            evidence_value=evidence_value,
            evidence_excerpt=excerpt,
            severity=severity,
            submission_id=self._submission_id,
        )
        self._evidences.append(ev)
        return ev

    def clear_evidences(self) -> None:
        """Clear all associated evidence items."""
        self._evidences.clear()

    # -------------------------------------------------------------------------
    # Lifecycle State Transitions
    # -------------------------------------------------------------------------

    def mark_processing(self) -> None:
        """Transition submission state to processing."""
        self._processing_status = "processing"
        self._error_message = None

    def mark_completed(
        self, assessment: Optional[AssessmentResult] = None
    ) -> None:
        """Mark submission completed and timestamp completion."""
        self._processing_status = "completed"
        self._completed_at = datetime.now(timezone.utc).isoformat()
        if assessment:
            self.set_assessment(assessment)

    def mark_failed(self, error_message: str) -> None:
        """Record an analysis failure with reason."""
        self._processing_status = "failed"
        self._error_message = str(error_message).strip()
        self._completed_at = datetime.now(timezone.utc).isoformat()

    # -------------------------------------------------------------------------
    # Static & Serialization Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def generate_hash(value: str) -> str:
        """Calculate the SHA-256 cryptographic digest of a string."""
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize submission to dictionary, including composed children."""
        return {
            "submission_id": self._submission_id,
            "data_origin": self._data_origin,
            "dataset_batch": self._dataset_batch,
            "input_type": self._input_type,
            "input_value": self._input_value,
            "input_hash": self._input_hash,
            "file_path": self._file_path,
            "interaction_type": self._interaction_type,
            "interaction_description": self._interaction_description,
            "processing_status": self._processing_status,
            "error_message": self._error_message,
            "created_at": self._created_at,
            "completed_at": self._completed_at,
            "assessment": (
                self._assessment.to_dict() if self._assessment else None
            ),
            "evidences": [ev.to_dict() for ev in self._evidences],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Submission":
        """Reconstitute a Submission from a dictionary representation."""
        assessment_data = data.get("assessment")
        assessment_obj = (
            AssessmentResult.from_dict(assessment_data)
            if assessment_data
            else None
        )

        evidences_data = data.get("evidences", [])
        evidence_objs = [
            ThreatEvidence.from_dict(ev) for ev in evidences_data
        ]

        return cls(
            submission_id=data.get("submission_id"),
            input_type=data.get("input_type", "text"),
            input_value=data.get("input_value", ""),
            input_hash=data.get("input_hash"),
            file_path=data.get("file_path"),
            interaction_type=data.get("interaction_type", "viewed_only"),
            interaction_description=data.get("interaction_description"),
            data_origin=data.get("data_origin", "cli"),
            dataset_batch=data.get("dataset_batch"),
            processing_status=data.get("processing_status", "pending"),
            error_message=data.get("error_message"),
            created_at=data.get("created_at"),
            completed_at=data.get("completed_at"),
            assessment=assessment_obj,
            evidences=evidence_objs,
        )

    def __repr__(self) -> str:
        return (
            f"Submission(id={self._submission_id}, type={self._input_type!r}, "
            f"status={self._processing_status!r})"
        )

    def __str__(self) -> str:
        return (
            f"Submission #{self._submission_id or 'NEW'} [{self._input_type.upper()}] "
            f"- Status: {self._processing_status.upper()}"
        )
