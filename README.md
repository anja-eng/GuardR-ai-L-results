# GuardR(ai)L — Companion Artifacts

Reproducibility package for:

> **GuardrAIl: A Neuro-Symbolic Framework for Automotive TARA Automation and ISO/SAE 21434 Compliance**
> Simić, Pavković, Milošević.
> *Information and Software Technology* (under review).

This repository contains the inputs, raw evaluation outputs, prompts, and
computed results behind the keyless entry case study reported in the paper:
**a staged ablation across five configurations, each run 5 times on the same
system specification, comparing a naive single-prompt LLM baseline against
the full framework.**

## Repository layout

```
├── inputs/
│   └── system_description.json          # Fixed system spec: 14 components, 18 data
│                                         #   flows, 6 trust boundaries, 24 assets
├── refs/
│   ├── atm_baseline.json                # 16-technique converged coverage target
│   ├── full_atm_ids.json                # All 77 techniques in the ATM catalog
│   └── all_asset_ids.json               # 42 asset and data-flow identifiers
├── outputs/
│   ├── c_0/                             # Naive single-prompt baseline, 5 runs
│   ├── c_1/                             # Decomposed, no audit loops, no grounding, 5 runs
│   ├── c_2/                             # + STRIDE and ATM completeness-audit loops, 5 runs
│   ├── c_3/                             # RQ2: grounded vs. ungrounded risk assessment
│   │   ├── threats_atm.json             #   threat set frozen at c_2's output
│   │   ├── grounded/                    #   5 runs, PR-RAG + deterministic calculation
│   │   └── ungrounded/                  #   5 runs, no retrieval, LLM states risk_value directly
│   └── c_4/                             # Full framework, 5 runs, each paired with
│                                         #   its own run_XX_goals.json
├── prompts/
│   └── prompts.py                       # System prompt text for all eight LLM-invoking agents
├── analysis/
│   ├── adapters.py                      # Normalizes each configuration's raw JSON into a common threat representation
│   ├── analyze_c3.py                    # ATM recall, structural coverage, EARS conformance, goal traceability, and metric definitions
│   ├── analyze.py                       # Scores c_0, c_1, c_2, c_4 -> results/summary.json
│   └── metrics.py                       # Scores c_3 (grounded vs. ungrounded) -> results/rq2_summary.json
└── results/
    ├── summary.json                     # Aggregated metrics (mean, std) per configuration
    ├── rq2_summary.json                 # Grounded vs. ungrounded comparison on the frozen set
    └── results_table.csv                # summary.json flattened into a single table
```


## Reproducing the reported statistics

```bash
python analysis/analyze.py         # writes results/summary.json
python analysis/analyze_rq2.py     # writes results/rq2_summary.json
```

Both scripts depend only on the Python standard library. `analyze_rq2.py`
additionally reports a Mann-Whitney U test if `scipy` is installed
(`pip install scipy`); without it, the script still runs and reports
everything else, just without that one optional test.

`analyze.py` scores `c_0`, `c_1`, `c_2`, and `c_4` against the reference sets
in `refs/`, computing ATM recall, ATM hallucination rate, structural
asset/data-flow coverage, STRIDE and treatment category validity, EARS
conformance, and (for `c_4`) goal traceability completeness, aggregating
mean and standard deviation across each configuration's 5 runs.

`analyze_rq2.py` scores `c_3` separately, since it is not a single flat
configuration: it matches each threat by identity (`component`,
position-in-list) across all repetitions of both the grounded and ungrounded
conditions on the same frozen threat set, then reports the pooled
distribution, per-threat rating variance, and the resulting mean shift
between conditions.

Notes on the data: all five configurations use the identical system
specification in `inputs/`; `c_0`–`c_2` and `c_4` each have exactly 5 runs,
with no runs excluded. The Automotive Threat Matrix
(https://atm.automotiveisac.com/) is not redistributed here and must be
obtained directly from Auto-ISAC; `refs/full_atm_ids.json` lists only the
technique identifiers used, and `refs/atm_baseline.json` is the framework's
own converged coverage target for this system, used as the ATM recall
denominator.


## Citation

```bibtex
@article{simic2026guardrail,
  title   = {GuardrAIl: A Neuro-Symbolic Framework for Automotive TARA Automation and ISO/SAE 21434 Compliance},
  author  = {Simić, Anja and Pavković, Bogdan and Milošević, Jelena},
  journal = {Information and Software Technology},
  year    = {2026},
  note    = {Companion artifacts: https://github.com/anja-eng/GuardrAIl-results}
}
```

## Licence

- **Code** (`analysis/`, `prompts/`) — Apache License 2.0 (see `LICENSE`).
- **Data** (`inputs/`, `refs/`, `outputs/`, `results/`) — Creative Commons
  Attribution 4.0 International (see `LICENSE-DATA`).
