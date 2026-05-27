# Security Issues Prioritization

## What This Is

An AI-assisted pipeline that takes raw security findings — the messy, inconsistent output of scanners, audits, and pentests — and produces a financially ranked remediation backlog. A large language model normalizes each finding into structured risk inputs, a Return on Security Investment (ROSI) calculation converts those inputs into dollar-denominated priorities, and a reporter emits a ranked CSV plus an executive-ready markdown summary.

## The Problem It Solves

Most security backlogs are sorted by a High / Medium / Low label that came out of whichever tool found the issue. The result is predictable:

- **Everything is Critical.** When fifteen scanners each apply their own severity scheme, "Critical" stops being a signal — it becomes the default for anything that doesn't look harmless.
- **No financial logic.** A "Critical" SQL injection on a customer-data endpoint and a "Critical" missing TLS 1.2 header on a marketing brochure site look identical in the queue, even though one carries six figures of expected annual loss and the other carries hundreds of dollars.
- **No defensible "what to fix first."** When a CISO asks why this issue is sitting above that one, the honest answer is usually "the scanner said so" — which is not an answer you can take to a finance committee.

This project replaces the label with a number. Every finding is reduced to an estimated Annualized Loss Expectancy (ALE), a remediation cost, and the ROSI multiple between them. The backlog is sorted by that multiple.

## How It Works

1. **LLM normalization.** Each raw finding (free-text scanner output) is passed to a calibrated system prompt that returns a strict JSON object: `risk_domain`, `severity`, `threat_frequency`, `vulnerability_probability`, `asset_value_usd`, `control_effectiveness`, `estimated_remediation_cost_usd`, `risk_reduction_pct`, and a one-line rationale. The prompt encodes CVSS → probability bands, CISA KEV overrides, and pentest-evidence overrides so two findings with similar text receive similar numbers.
2. **ROSI scoring.** The structured inputs feed a deterministic FAIR-style calculation:
   - `ALE = asset_value × threat_frequency × vulnerability_probability × (1 − control_effectiveness)`
   - `Residual ALE = ALE × (1 − risk_reduction_pct)`
   - `ROSI = (ALE − Residual ALE − Remediation Cost) / Remediation Cost`
   Findings are then bucketed into five priority tiers (Immediate → Deprioritize) by ROSI multiple.
3. **Ranked backlog.** The full set is sorted by ROSI, printed as a terminal table, written to `output/ranked_remediation_backlog.csv`, and summarized in `output/executive_summary.md` with a portfolio overview, a top-5 table, and a recommended sprint plan with target dates derived from each finding's tier.

## Architecture

```
.
├── data/
│   └── sample_issues.csv          # 15 raw findings across 8 source types
├── src/
│   ├── normalizer.py              # LLM call + JSON parsing + calibration prompt
│   ├── scorer.py                  # ALE / residual ALE / ROSI / priority tier
│   └── reporter.py                # Terminal table, CSV writer, markdown writer
├── output/                        # Generated; created on first run
│   ├── ranked_remediation_backlog.csv
│   └── executive_summary.md
├── prioritize.ipynb               # Notebook that wires the three modules together
├── requirements.txt
└── README.md
```

- **`src/normalizer.py`** — exposes `normalize_finding(raw_description, source_tool) -> dict`. Calls a local LLM via the `ollama` Python package using `format='json'` for structured output. Strips markdown fences defensively and returns a dict of `None`s + an `error` field if anything fails to parse.
- **`src/scorer.py`** — exposes the four math primitives (`calculate_ale`, `calculate_residual_ale`, `calculate_rosi`, `assign_priority_tier`) plus `score_issue(normalized) -> dict` which runs the whole chain and returns a combined record with ALE, residual ALE, financial benefit, ROSI, priority tier, and recommended action.
- **`src/reporter.py`** — exposes `generate_report(scored_issues) -> None`. Sorts by ROSI desc, prints a `tabulate` table to stdout, prints a portfolio summary block, writes the full backlog (including the LLM's rationale field) to CSV, and writes a stakeholder-facing markdown report with a top-5 sprint plan.
- **`prioritize.ipynb`** — seven cells: imports → load CSV → normalize with progress bar → score → report → three matplotlib/seaborn charts → export paths.

## How to Run

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install and start the local LLM backend
#    (uses Ollama; swap-point is src/normalizer.py if you prefer a hosted API)
ollama pull llama3.1:8b
ollama serve

# 3. (Optional) override defaults via .env
echo "OLLAMA_MODEL=llama3.1:8b"            >  .env
echo "OLLAMA_HOST=http://localhost:11434"  >> .env

# 4. Launch the notebook and run all cells
jupyter notebook prioritize.ipynb
```

> **Note on the LLM backend.** Normalization runs against a local Ollama model (`llama3.1:8b` by default), so the pipeline works offline with no paid API key. The entire LLM integration is isolated to `src/normalizer.py` — the calibration prompt, JSON parsing, and downstream ROSI scoring are provider-agnostic, so swapping in a different model or a hosted provider is a one-function change.

## Methodology

The scoring model is a simplified, single-issue variant of the **FAIR (Factor Analysis of Information Risk)** framework — see *Measuring and Managing Information Risk: A FAIR Approach* (Freund & Jones, 2014) and the **Open FAIR** standards (Open Group, O-RA / O-RT). FAIR decomposes risk into Loss Event Frequency × Loss Magnitude; this project's `threat_frequency × vulnerability_probability` is the LEF component and `asset_value × (1 − control_effectiveness)` is the LM component, scaled annually.

Probability calibration draws from the **Verizon Data Breach Investigations Report (DBIR)** — annualized attack-attempt rates against internet-facing services, the long-known dominance of credential and web-application vectors, and the empirical distribution of CVSS scores observed in breaches. CISA KEV-listed vulnerabilities are floored at a higher `threat_frequency` because the catalog is, by definition, evidence of in-the-wild exploitation.

Control-effectiveness ranges are anchored to **NIST SP 800-53 Rev. 5** control families — when the LLM reads "MFA enforced," "WAF in front," "EDR present," or "network segmented," it should bias `control_effectiveness` upward in proportion to which 800-53 families those controls cover (AC, SC, SI, IA). Remediation cost estimates draw on industry-published patch-management labor estimates and typical engineering-day rates.

The framework does not claim to predict any individual loss event. It claims to produce a **consistent, defensible ordering** — given two findings, the one with the higher ROSI should be fixed first, and the reason can be shown in dollars.

## Sample Output

> _Placeholder — add a screenshot of the terminal ranked table and one of the notebook charts here after the first run._

## About the Author

> _Placeholder._
