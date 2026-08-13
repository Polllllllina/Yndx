"""Compatibility re-exports for the shared normalization implementation."""

from common.normalization import (
    NormalizedText,
    SUSPICIOUS_CONTROLS,
    normalize_text,
)

__all__ = ["NormalizedText", "SUSPICIOUS_CONTROLS", "normalize_text"]
