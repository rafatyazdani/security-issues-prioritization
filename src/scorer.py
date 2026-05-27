"""ROSI-based scoring for normalized security findings.

Pipeline: normalized LLM output -> ALE -> residual ALE -> ROSI -> priority tier.
"""

from typing import Any


def calculate_ale(
    asset_value: float,
    threat_frequency: float,
    vulnerability_probability: float,
    control_effectiveness: float,
) -> float:
    """Compute the Annualized Loss Expectancy (ALE) for a finding.

    ALE = asset_value * threat_frequency * vulnerability_probability * (1 - control_effectiveness)

    Args:
        asset_value: Dollar value of the asset at risk.
        threat_frequency: Annualized probability (0–1) of an attack attempt.
        vulnerability_probability: Probability (0–1) that an attempt succeeds.
        control_effectiveness: Existing-control mitigation factor (0 = none, 1 = full).

    Returns:
        Expected annualized loss in dollars.
    """
    return (
        asset_value
        * threat_frequency
        * vulnerability_probability
        * (1 - control_effectiveness)
    )


def calculate_residual_ale(ale: float, risk_reduction_pct: float) -> float:
    """Compute the residual ALE that remains after remediation.

    Residual ALE = ALE * (1 - risk_reduction_pct)

    Args:
        ale: Current annualized loss expectancy in dollars.
        risk_reduction_pct: Expected proportional ALE reduction (0–1) after fix.

    Returns:
        Residual annualized loss in dollars after the fix is applied.
    """
    return ale * (1 - risk_reduction_pct)


def calculate_rosi(ale: float, residual_ale: float, remediation_cost: float) -> float:
    """Compute Return on Security Investment (ROSI) as a multiple.

    ROSI = (ALE - residual_ale - remediation_cost) / remediation_cost

    A ROSI of 5 means every $1 spent on remediation avoids $6 of expected loss
    (net $5 benefit).

    Args:
        ale: Annualized loss expectancy before remediation.
        residual_ale: Annualized loss expectancy after remediation.
        remediation_cost: One-time dollar cost of remediation.

    Returns:
        ROSI as a unit-less multiple. Returns 0 when remediation_cost is 0 to
        avoid division by zero.
    """
    if remediation_cost == 0:
        return 0.0
    return (ale - residual_ale - remediation_cost) / remediation_cost


def assign_priority_tier(rosi: float) -> str:
    """Map a ROSI multiple to a discrete priority tier.

    Tiers:
        TIER 1 — IMMEDIATE:     ROSI > 20x
        TIER 2 — HIGH PRIORITY: 10x <= ROSI <= 20x
        TIER 3 — STANDARD:      3x  <= ROSI < 10x
        TIER 4 — MONITOR:       1x  <= ROSI < 3x
        TIER 5 — DEPRIORITIZE:  ROSI < 1x

    Args:
        rosi: ROSI multiple from calculate_rosi.

    Returns:
        Tier label string.
    """
    if rosi > 20:
        return "TIER 1 — IMMEDIATE"
    if rosi >= 10:
        return "TIER 2 — HIGH PRIORITY"
    if rosi >= 3:
        return "TIER 3 — STANDARD"
    if rosi >= 1:
        return "TIER 4 — MONITOR"
    return "TIER 5 — DEPRIORITIZE"


_RECOMMENDED_ACTION = {
    "TIER 1 — IMMEDIATE": "Remediate within 48 hours; escalate to incident response and notify CISO.",
    "TIER 2 — HIGH PRIORITY": "Schedule remediation within the current sprint (≤2 weeks).",
    "TIER 3 — STANDARD": "Include in next quarterly remediation cycle.",
    "TIER 4 — MONITOR": "Track in backlog; revisit if asset value or threat landscape changes.",
    "TIER 5 — DEPRIORITIZE": "Accept risk or bundle with adjacent work; remediation cost exceeds expected benefit.",
}


def score_issue(normalized: dict[str, Any]) -> dict[str, Any]:
    """Run the full ROSI pipeline on a normalized finding.

    Takes the dict returned by `normalizer.normalize_finding` and produces a
    combined dict containing every input field plus the derived financial
    metrics and tier assignment.

    Args:
        normalized: Output of the LLM normalizer. Must contain asset_value_usd,
            threat_frequency, vulnerability_probability, control_effectiveness,
            risk_reduction_pct, and estimated_remediation_cost_usd.

    Returns:
        A dict with all original fields plus ale, residual_ale,
        financial_benefit, rosi, priority_tier, recommended_action.
    """
    required = (
        "asset_value_usd",
        "threat_frequency",
        "vulnerability_probability",
        "control_effectiveness",
        "risk_reduction_pct",
        "estimated_remediation_cost_usd",
    )
    if any(normalized.get(f) is None for f in required):
        return {
            **normalized,
            "ale": None,
            "residual_ale": None,
            "financial_benefit": None,
            "rosi": None,
            "priority_tier": None,
            "recommended_action": None,
            "scoring_error": "missing one or more required normalized fields",
        }

    asset_value = float(normalized["asset_value_usd"])
    threat_frequency = float(normalized["threat_frequency"])
    vulnerability_probability = float(normalized["vulnerability_probability"])
    control_effectiveness = float(normalized["control_effectiveness"])
    risk_reduction_pct = float(normalized["risk_reduction_pct"])
    remediation_cost = float(normalized["estimated_remediation_cost_usd"])

    ale = calculate_ale(
        asset_value,
        threat_frequency,
        vulnerability_probability,
        control_effectiveness,
    )
    residual_ale = calculate_residual_ale(ale, risk_reduction_pct)
    rosi = calculate_rosi(ale, residual_ale, remediation_cost)
    financial_benefit = ale - residual_ale - remediation_cost
    tier = assign_priority_tier(rosi)

    return {
        **normalized,
        "ale": round(ale, 2),
        "residual_ale": round(residual_ale, 2),
        "financial_benefit": round(financial_benefit, 2),
        "rosi": round(rosi, 2),
        "priority_tier": tier,
        "recommended_action": _RECOMMENDED_ACTION[tier],
    }
