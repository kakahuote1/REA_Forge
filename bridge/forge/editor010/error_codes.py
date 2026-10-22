"""Failure vocabulary used only by the standalone binary-editing helper."""

from enum import StrEnum


class ErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    POLICY_HARD_DENY = "POLICY_HARD_DENY"
    EVIDENCE_WRITE_FAILED = "EVIDENCE_WRITE_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
