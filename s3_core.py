"""
s3_core
=======
Pure, dependency-free core logic for Startup Security Shield.

This module deliberately imports nothing from FastAPI, Presidio, or the
database layer. Everything here is a pure function of its inputs, which makes
it fast to unit test without loading the ML stack. main.py wires these
functions into the request handlers.

The risk-scoring functions accept any iterable of objects that expose two
attributes, `entity_type` (str) and `score` (float in 0..1). Presidio's
RecognizerResult satisfies that, and so does a plain namedtuple in tests.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Default per-entity risk configuration.
#
# base_risk:  starting point for one high-confidence instance of this type
# level:      coarse label used in the UI
# decay:      how quickly repeated instances of the same type stop adding risk
#             (lower = faster diminishing returns)
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_ENTITY_RISKS: Dict[str, Dict[str, Any]] = {
    # Critical (35-50)
    "US_SSN": {"risk": 50.0, "level": "critical", "decay": 0.75, "desc": "Social Security Number"},
    "CREDIT_CARD": {"risk": 45.0, "level": "critical", "decay": 0.75, "desc": "Payment card number"},
    "PASSWORD": {"risk": 48.0, "level": "critical", "decay": 0.70, "desc": "Authentication credential"},
    "MEDICAL_LICENSE": {"risk": 42.0, "level": "critical", "decay": 0.75, "desc": "Protected health information"},
    "US_PASSPORT": {"risk": 40.0, "level": "critical", "decay": 0.80, "desc": "Government identification"},
    "US_BANK_NUMBER": {"risk": 43.0, "level": "critical", "decay": 0.75, "desc": "Financial account number"},
    "CRYPTO": {"risk": 38.0, "level": "critical", "decay": 0.80, "desc": "Cryptocurrency wallet address"},
    # High (20-34)
    "US_DRIVER_LICENSE": {"risk": 30.0, "level": "high", "decay": 0.82, "desc": "State identification"},
    "US_ITIN": {"risk": 32.0, "level": "high", "decay": 0.80, "desc": "Individual Taxpayer ID"},
    "IBAN_CODE": {"risk": 28.0, "level": "high", "decay": 0.85, "desc": "International bank account"},
    "EMAIL_ADDRESS": {"risk": 22.0, "level": "high", "decay": 0.88, "desc": "Email address"},
    "PHONE_NUMBER": {"risk": 20.0, "level": "high", "decay": 0.88, "desc": "Phone number"},
    "IP_ADDRESS": {"risk": 25.0, "level": "high", "decay": 0.85, "desc": "Network identifier"},
    "UK_NHS": {"risk": 33.0, "level": "high", "decay": 0.80, "desc": "NHS number"},
    "EMPLOYEE_ID": {"risk": 24.0, "level": "high", "decay": 0.86, "desc": "Employee identification"},
    # Medium (10-19)
    "DATE_TIME": {"risk": 12.0, "level": "medium", "decay": 0.90, "desc": "Date of birth or temporal data"},
    "LOCATION": {"risk": 15.0, "level": "medium", "decay": 0.88, "desc": "Physical address or location"},
    "PERSON": {"risk": 14.0, "level": "medium", "decay": 0.88, "desc": "Personal name"},
    "USERNAME": {"risk": 16.0, "level": "medium", "decay": 0.87, "desc": "Account username"},
    "VEHICLE_INFO": {"risk": 18.0, "level": "medium", "decay": 0.86, "desc": "Vehicle or license plate"},
    # Low (5-9)
    "URL": {"risk": 6.0, "level": "low", "decay": 0.92, "desc": "Web address"},
}

UNKNOWN_ENTITY_CONFIG: Dict[str, Any] = {
    "base_risk": 10.0,
    "level": "medium",
    "decay": 0.90,
    "description": "Unknown entity type",
}

# How much an entity's weight is increased when it is flagged high-risk by the
# selected compliance framework.
COMPLIANCE_RISK_MULTIPLIER = 1.3

# Decay used for custom (admin-defined) entity weights.
CUSTOM_ENTITY_DECAY = 0.85


def default_risk_config(entity_type: str) -> Dict[str, Any]:
    """Return the built-in risk config for an entity type, or a safe default."""
    cfg = DEFAULT_ENTITY_RISKS.get(entity_type)
    if cfg is None:
        return dict(UNKNOWN_ENTITY_CONFIG)
    return {
        "base_risk": cfg["risk"],
        "level": cfg["level"],
        "decay": cfg["decay"],
        "description": cfg["desc"],
    }


def calculate_risk_score(
    entities: Iterable[Any],
    get_risk_config: Optional[Callable[[str], Dict[str, Any]]] = None,
    high_risk_entities: Optional[List[str]] = None,
    custom_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Score detected PII on a 0-100 scale.

    The algorithm has four moving parts:
      1. Diminishing returns. Repeated instances of the same entity type each
         add less than the previous one (base_risk * confidence * decay**i).
      2. Diversity. More distinct entity types is riskier than more copies of
         one type, applied as a logarithmic multiplier.
      3. Volume. Total count nudges the score up, also logarithmic so a huge
         dump does not trivially saturate the scale.
      4. Soft ceiling. A sigmoid maps unbounded raw risk into 0-100 and caps
         at 99.5, so the score degrades gracefully instead of pinning at 100.

    `get_risk_config(entity_type)` should return a dict with `base_risk` and
    `decay`. If omitted, the built-in defaults are used. `high_risk_entities`
    is the list of types the active compliance framework treats as high risk.
    """
    entities = list(entities)
    if get_risk_config is None:
        get_risk_config = default_risk_config
    high_risk_entities = high_risk_entities or []

    if not entities:
        return {
            "score": 0,
            "level": "safe",
            "breakdown": {},
            "diversity_score": 0,
            "volume_factor": 0,
            "entity_types_count": 0,
            "total_entities": 0,
            "compliance_adjusted": bool(high_risk_entities),
        }

    # Group confidences by entity type.
    entity_groups: Dict[str, List[float]] = {}
    for entity in entities:
        entity_groups.setdefault(entity.entity_type, []).append(entity.score)

    # Resolve per-type base risk and decay.
    entity_risks: Dict[str, float] = {}
    decay_factors: Dict[str, float] = {}
    for etype in entity_groups:
        if custom_weights and etype in custom_weights:
            entity_risks[etype] = custom_weights[etype]
            decay_factors[etype] = CUSTOM_ENTITY_DECAY
        else:
            cfg = get_risk_config(etype)
            entity_risks[etype] = cfg["base_risk"]
            decay_factors[etype] = cfg.get("decay", 0.90)

    # Compliance bump for framework-critical entities.
    for etype in entity_groups:
        if etype in high_risk_entities:
            entity_risks[etype] *= COMPLIANCE_RISK_MULTIPLIER

    # Per-type contribution with diminishing returns.
    total_risk = 0.0
    breakdown: Dict[str, Any] = {}
    for etype, confidences in entity_groups.items():
        base_risk = entity_risks.get(etype, 10.0)
        decay_factor = decay_factors.get(etype, 0.90)
        confidences.sort(reverse=True)

        contribution = 0.0
        for i, confidence in enumerate(confidences):
            contribution += base_risk * confidence * (decay_factor ** i)

        breakdown[etype] = {
            "count": len(confidences),
            "contribution": round(contribution, 2),
            "base_risk": base_risk,
            "avg_confidence": round(sum(confidences) / len(confidences), 3),
        }
        total_risk += contribution

    num_types = len(entity_groups)
    diversity_multiplier = 1.0 + (math.log(num_types + 1) * 0.15)

    total_count = len(entities)
    volume_factor = 1.0 + (math.log(total_count + 1) * 0.10)

    adjusted_risk = total_risk * diversity_multiplier * volume_factor

    final_score = 100 * (1 - math.exp(-adjusted_risk / 100))
    final_score = min(final_score, 99.5)

    return {
        "score": round(final_score, 1),
        "level": score_to_level(final_score),
        "breakdown": breakdown,
        "diversity_score": round(diversity_multiplier, 2),
        "volume_factor": round(volume_factor, 2),
        "entity_types_count": num_types,
        "total_entities": total_count,
        "compliance_adjusted": bool(high_risk_entities),
    }


def score_to_level(score: float) -> str:
    """Map a 0-100 score to a coarse risk band."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "minimal"


def decide_from_score(score: float, risk_threshold: int = 50) -> Tuple[str, str]:
    """
    Turn a numeric score into an action plus a human-readable reason.

    Returns one of: block, review, warn, caution, allow. The caller can set a
    per-policy `risk_threshold`; the review and warn bands never trip below
    their floors (60 and 35) even if the threshold is set lower.
    """
    if score >= 80:
        return "block", f"CRITICAL RISK (score: {score}/100) - Immediate action required"
    if score >= max(risk_threshold, 60):
        return "review", f"HIGH RISK (score: {score}/100) - Manual review mandatory"
    if score >= max(risk_threshold * 0.7, 35):
        return "warn", f"MODERATE RISK (score: {score}/100) - Proceed with caution"
    if score >= 15:
        return "caution", f"LOW RISK (score: {score}/100) - Standard precautions apply"
    return "allow", f"MINIMAL RISK (score: {score}/100) - Safe to proceed"


# ──────────────────────────────────────────────────────────────────────────────
# Regex safety
# ──────────────────────────────────────────────────────────────────────────────

# Nested quantifiers like (a+)+ or (a*)* are the classic catastrophic
# backtracking shape. This is a heuristic, not a proof of safety, but it blocks
# the obvious foot-guns when an admin supplies a custom entity pattern.
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")


def is_valid_regex(pattern: str) -> bool:
    """True if the pattern compiles as a regular expression."""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def is_dangerous_regex(pattern: str) -> bool:
    """True if the pattern contains an obvious ReDoS (nested quantifier) shape."""
    return bool(_NESTED_QUANTIFIER.search(pattern))
