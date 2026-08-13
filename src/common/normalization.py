"""Deterministic, immutable text views shared across runtime services."""

from __future__ import annotations

from dataclasses import dataclass
from unicodedata import normalize


# Invisible format characters commonly used to split tokens or alter display
# direction. They are retained in ``normalized`` for auditability and removed
# only from ``control_stripped``.
SUSPICIOUS_CONTROLS = frozenset(
    "\u00ad"  # SOFT HYPHEN
    "\u061c"  # ARABIC LETTER MARK
    "\u180e"  # MONGOLIAN VOWEL SEPARATOR
    "\u200b\u200c\u200d"  # zero-width space/non-joiner/joiner
    "\u200e\u200f"  # left-to-right/right-to-left marks
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embeddings/overrides
    "\u2060\u2061\u2062\u2063\u2064"  # invisible word/math controls
    "\u2066\u2067\u2068\u2069"  # bidi isolates
    "\u206a\u206b\u206c\u206d\u206e\u206f"  # deprecated bidi controls
    "\ufeff"  # zero-width no-break space / BOM
)


@dataclass(frozen=True, slots=True)
class NormalizedText:
    """The original text and two deterministic normalized views."""

    raw: str
    normalized: str
    control_stripped: str
    has_suspicious_controls: bool


def _collapse_whitespace(text: str) -> str:
    return " ".join(text.split())


def normalize_text(text: str) -> NormalizedText:
    """Return NFKC/casefolded views while preserving the raw input."""

    normalized = _collapse_whitespace(normalize("NFKC", text).casefold())
    has_suspicious_controls = any(
        character in SUSPICIOUS_CONTROLS for character in normalized
    )
    control_stripped = _collapse_whitespace(
        "".join(
            character
            for character in normalized
            if character not in SUSPICIOUS_CONTROLS
        )
    )
    return NormalizedText(
        raw=text,
        normalized=normalized,
        control_stripped=control_stripped,
        has_suspicious_controls=has_suspicious_controls,
    )
