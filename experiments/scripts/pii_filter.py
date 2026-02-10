"""
PII filter: check text for personally identifiable information.

Supports:
- regex: built-in patterns (email, SSN, phone, etc.)
- transformers: local token-classification via obi/deid_roberta_i2b2
- hf_api: remote token-classification via Hugging Face InferenceClient (requires HF_TOKEN)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class PIIResult:
    """Result of a PII check."""

    passed: bool
    """True if no PII was detected."""
    method: str
    """One of 'regex', 'transformers', 'hf_api'."""
    matches: list[dict[str, Any]] = field(default_factory=list)
    """List of detected PII spans: [{"label": str, "start": int, "end": int}, ...]."""

    def __post_init__(self) -> None:
        if self.matches is None:
            self.matches = []


# ---------------------------------------------------------------------------
# Regex-based PII detection
# ---------------------------------------------------------------------------

# Patterns: (compiled_re, label). Order matters for first-match semantics if we ever short-circuit.
_REGEX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Email (simple)
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "EMAIL"),
    # US SSN: 123-45-6789 or 123456789
    (re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"), "SSN"),
    # US / international phone: +1..., (123) 456-7890, 123-456-7890, etc.
    (re.compile(r"\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "PHONE"),
    (re.compile(r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"), "PHONE"),
    # Credit-card-like: 4 groups of 4 digits, optional spaces/dashes
    (re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"), "CARD"),
]


def _check_pii_regex(text: str) -> PIIResult:
    matches: list[dict[str, Any]] = []
    for pattern, label in _REGEX_PATTERNS:
        for m in pattern.finditer(text):
            matches.append({"label": label, "start": m.start(), "end": m.end()})
    return PIIResult(passed=len(matches) == 0, method="regex", matches=matches)


# ---------------------------------------------------------------------------
# Transformers pipeline (local obi/deid_roberta_i2b2)
# ---------------------------------------------------------------------------


def _check_pii_transformers(text: str) -> PIIResult:
    try:
        from transformers import pipeline
    except ImportError as e:
        raise ImportError(
            "PII method 'transformers' requires: pip install transformers torch"
        ) from e

    pipe = pipeline(
        "token-classification",
        model="obi/deid_roberta_i2b2",
        aggregation_strategy="simple",
    )
    entities = pipe(text) or []
    # Any entity is PII (DATE, PATIENT, PHONE, etc.)
    matches = [
        {"label": e.get("entity_group", e.get("entity", "PHI")), "start": e["start"], "end": e["end"]}
        for e in entities
    ]
    return PIIResult(passed=len(matches) == 0, method="transformers", matches=matches)


# ---------------------------------------------------------------------------
# Hugging Face Inference API (remote)
# ---------------------------------------------------------------------------


def _check_pii_hf_api(text: str, api_key: str | None = None) -> PIIResult:
    try:
        import os
        from huggingface_hub import InferenceClient
    except ImportError as e:
        raise ImportError(
            "PII method 'hf_api' requires: pip install huggingface_hub"
        ) from e

    token = api_key or os.environ.get("HF_TOKEN")
    if not token:
        raise ValueError(
            "PII method 'hf_api' requires HF_TOKEN in environment or api_key=..."
        )
    client = InferenceClient(provider="hf-inference", api_key=token)
    result = client.token_classification(
        text,
        model="obi/deid_roberta_i2b2",
    )
    # result is typically a list of entity dicts or objects (entity_group, start, end)
    entities = list(result) if result else []
    matches = []
    for e in entities:
        label = e.get("entity_group", e.get("entity", "PHI")) if isinstance(e, dict) else getattr(e, "entity_group", None) or getattr(e, "entity", "PHI")
        start = e.get("start", 0) if isinstance(e, dict) else getattr(e, "start", 0)
        end = e.get("end", 0) if isinstance(e, dict) else getattr(e, "end", 0)
        matches.append({"label": label, "start": start, "end": end})
    return PIIResult(passed=len(matches) == 0, method="hf_api", matches=matches)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

Method = Literal["regex", "transformers", "hf_api"]


def check_pii(
    text: str,
    method: Method = "regex",
    *,
    api_key: str | None = None,
) -> PIIResult:
    """
    Check text for PII.

    Args:
        text: The string to check (e.g. LLM output).
        method: 'regex' (stdlib), 'transformers' (local obi/deid_roberta_i2b2),
                or 'hf_api' (Hugging Face Inference API; needs HF_TOKEN or api_key).
        api_key: For method='hf_api', optional override for HF_TOKEN.

    Returns:
        PIIResult with passed=True if no PII, else passed=False and matches list.
    """
    if not text or not text.strip():
        return PIIResult(passed=True, method=method, matches=[])

    logger.info("PII check starting: method=%s, text_len=%d", method, len(text))

    if method == "regex":
        result = _check_pii_regex(text)
    elif method == "transformers":
        result = _check_pii_transformers(text)
    elif method == "hf_api":
        result = _check_pii_hf_api(text, api_key=api_key)
    else:
        raise ValueError(f"Unknown method: {method!r}. Use 'regex', 'transformers', or 'hf_api'.")

    logger.info(
        "PII check finished: method=%s, passed=%s, num_matches=%d",
        result.method,
        result.passed,
        len(result.matches),
    )
    return result


# ---------------------------------------------------------------------------
# CLI for quick tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    sample = (
        "My name is Sarah Jessica Parker but you can call me Jessica."
        if len(sys.argv) <= 1
        else " ".join(sys.argv[1:])
    )
    method: Method = "regex"
    if "--transformers" in sys.argv:
        method = "transformers"
        sys.argv.remove("--transformers")
        sample = " ".join(a for a in sys.argv[1:] if a != "--transformers") or sample
    elif "--hf" in sys.argv:
        method = "hf_api"
        sys.argv.remove("--hf")
        sample = " ".join(a for a in sys.argv[1:] if a != "--hf") or sample

    if not sample.strip():
        sample = "My name is Sarah Jessica Parker but you can call me Jessica."

    res = check_pii(sample, method=method)
    print("passed:", res.passed)
    print("matches:", res.matches)
