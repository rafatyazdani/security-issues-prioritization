import json
import os
import re

import ollama
from dotenv import load_dotenv

load_dotenv()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

_EXPECTED_FIELDS = (
    "risk_domain",
    "severity",
    "threat_frequency",
    "vulnerability_probability",
    "asset_value_usd",
    "control_effectiveness",
    "estimated_remediation_cost_usd",
    "risk_reduction_pct",
    "normalization_rationale",
)

SYSTEM_PROMPT = """You are a cyber risk quantification analyst. You translate raw security findings into structured inputs for a FAIR-style Annualized Loss Expectancy (ALE) calculation.

You will receive a raw finding description and the name of the source tool that produced it. Return ONLY a single valid JSON object — no prose, no markdown fences, no commentary before or after.

The JSON object MUST contain exactly these fields:

- risk_domain: one of "Infrastructure", "Application", "Identity & Access", "Data Protection", "Network Security", "Endpoint Security", "Detection & Response", "Third-Party Risk".
- severity: one of "Critical", "High", "Medium", "Low".
- threat_frequency: float in [0, 1]. Annualized probability that an attacker attempts to exploit this finding.
- vulnerability_probability: float in [0, 1]. Probability that an attempt succeeds given current controls.
- asset_value_usd: integer. Estimated dollar value of the asset / data at risk.
- control_effectiveness: float in [0, 1]. 0 = no compensating controls, 1 = fully mitigated by other controls.
- estimated_remediation_cost_usd: integer. Approximate cost in dollars to remediate.
- risk_reduction_pct: float in [0, 1]. Expected proportional reduction in ALE if the finding is remediated.
- normalization_rationale: 1–2 sentence explanation of how you derived the numeric values.

Calibration guidance — apply these consistently:

CVSS → threat_frequency (annualized attempt rate):
  - CVSS 9.0–10.0  → 0.70–0.95
  - CVSS 7.0–8.9   → 0.45–0.70
  - CVSS 4.0–6.9   → 0.20–0.45
  - CVSS < 4.0     → 0.05–0.20

CVSS → vulnerability_probability (exploit success likelihood):
  - CVSS 9.0–10.0  → 0.75–0.95
  - CVSS 7.0–8.9   → 0.55–0.75
  - CVSS 4.0–6.9   → 0.25–0.55
  - CVSS < 4.0     → 0.05–0.25

Source-specific overrides:
  - If the finding is on the CISA Known Exploited Vulnerabilities (KEV) catalog, or the description mentions active exploitation / in-the-wild / KEV / ransomware use, set threat_frequency >= 0.7.
  - If source_tool indicates a manual penetration test ("Manual Pentest", "Pentest", "Red Team") AND the description demonstrates a successful exploit (extracted data, proven RCE, session hijack, etc.), set vulnerability_probability >= 0.8.
  - Internet-facing / unauthenticated findings should bias both probabilities upward within their CVSS band.
  - Findings requiring physical or local-only access should bias threat_frequency to the lower half of its band.

Asset value heuristics (use the description to pick):
  - Customer PII / financial / PHI data store: 500_000 – 5_000_000
  - Production application or core infra host: 100_000 – 1_000_000
  - Internal tooling / dev environment: 10_000 – 100_000
  - Marketing site / non-sensitive asset: 5_000 – 50_000

If a value cannot be inferred, choose the midpoint of the most defensible range and say so in the rationale. Never return null or "unknown" — always commit to a number.

Output: a single JSON object. Nothing else."""


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```$", text, re.DOTALL | re.IGNORECASE)
    if fence:
        return fence.group(1).strip()
    return text


def _empty_result(error: str) -> dict:
    result = {field: None for field in _EXPECTED_FIELDS}
    result["error"] = error
    return result


def normalize_finding(raw_description: str, source_tool: str) -> dict:
    user_prompt = (
        f"source_tool: {source_tool}\n"
        f"raw_description: {raw_description}\n\n"
        "Return the JSON object now."
    )

    try:
        client = ollama.Client(host=OLLAMA_HOST)
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            format="json",
            options={"temperature": 0.2},
        )
    except Exception as exc:
        return _empty_result(f"ollama request failed: {exc}")

    content = response.get("message", {}).get("content", "")
    if not content:
        return _empty_result("empty response from model")

    cleaned = _strip_markdown_fences(content)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return _empty_result(f"json decode failed: {exc}; raw={cleaned[:200]}")

    if not isinstance(parsed, dict):
        return _empty_result(f"expected JSON object, got {type(parsed).__name__}")

    missing = [f for f in _EXPECTED_FIELDS if f not in parsed]
    if missing:
        parsed["error"] = f"missing fields: {missing}"

    return parsed
