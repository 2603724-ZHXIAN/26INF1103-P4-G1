"""Domain models package.

Exports the core domain entities used across the application:
- Submission: Aggregate root managing user input and analysis lifecycle
- AssessmentResult: Final security risk verdict and recovery actions
- ThreatEvidence: Atomic indicator or telemetry proof
"""

from .assessment import AssessmentResult
from .evidence import ThreatEvidence
from .submission import Submission

__all__ = ["Submission", "AssessmentResult", "ThreatEvidence"]
