from importlib.metadata import PackageNotFoundError, version as _metadata_version

from .core import (
    DIRECTIONS,
    SCHEMA_VERSION,
    VERDICTS,
    CanaryEvaluation,
    CanaryLedger,
    CanaryValidationError,
    MetricObservation,
    canonical_json,
    evaluate_canary,
    sha256_ref,
    verify_ledger,
)

__all__ = [
    "DIRECTIONS",
    "SCHEMA_VERSION",
    "VERDICTS",
    "CanaryEvaluation",
    "CanaryLedger",
    "CanaryValidationError",
    "MetricObservation",
    "canonical_json",
    "evaluate_canary",
    "sha256_ref",
    "verify_ledger",
]

try:
    __version__ = _metadata_version("neuruh-canary-evaluation-ledger")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "unknown"
