# Synthetic Account Takeover (ATO) Behavior Generator — V3.2

A configurable **synthetic** data generator for research on a single question:

> Can post-login behavioral activity improve account takeover detection compared with authentication data alone?

The generator creates timestamped authentication records, session-linked post-login actions, and separate ground-truth labels for four post-login attacker objectives:

- Account security takeover (`security_takeover`)
- Financial redirection (`financial_redirection`)
- Unauthorized access-control changes (`access_control_change`)
- Sensitive data access (`sensitive_data_access`)

Three **illustrative** application profiles are provided: marketplace, business banking, and SaaS. These are configurable examples, **not externally validated simulators of actual businesses or banks**.

## Requirements

Python **3.11+**, no third-party packages required for generation or validation.

## Quick start

Clone/download this repository, open a terminal in its folder, then generate a small dataset:

```bash
python generate_ato_v3.py --seed 42 --accounts 100 --days 30 --cases-per-objective 3 --platform all --out ./ato_v3_small
python validate_ato_v3.py --data ./ato_v3_small --report ./ato_v3_small/validation_report.json
```

Generate the research-scale example (may take longer and use significant disk space):

```bash
python generate_ato_v3.py --seed 42 --accounts 2500 --days 90 --cases-per-objective 90 --platform all --out ./ato_v3_full
python validate_ato_v3.py --data ./ato_v3_full --report ./ato_v3_full/validation_report.json
```

Inspect `generation_manifest.json`, `validation_report.json`, and the generated CSVs. The raw data are **not included** in this source-only repository; they can be reproduced using the commands above.

## Files in this repository

| File | Purpose |
| --- | --- |
| `generate_ato_v3.py` | Main synthetic-data generator |
| `platform_profiles.json` | Configurable application-specific action labels |
| `validate_ato_v3.py` | Structural, chronological, label, and overlap checks |
| `audit_behavioral_overlap.py` | Diagnostic audit of simple shortcuts and benign/malicious overlap |
| `METHODOLOGY_AND_LIMITATIONS.md` | Simulator assumptions, threats to validity, and experimental cautions |
| `CHANGELOG.md` | Version history |

Generated data include `sessions.csv`, `authentication_events.csv`, `activity_events.csv`, `account_reference.csv`, `role_assignments.csv`, `session_ground_truth.csv`, `episode_ground_truth.csv`, and `observed_training_labels.csv`.

## What the generator **does not** establish

- These records are entirely invented, not anonymized production logs.
- Action probabilities, geo/network distributions, attacker timing, and fraud prevalence are **simulation assumptions**.
- Passing validation does **not** show that the data statistically resemble production telemetry.
- Template-based behavior could create learnable simulation artifacts. Test with independent seeds, changed parameters, and, ideally, external sources.
- Synthetic classifiers' precision or recall **must not** be claimed as real-world ATO detection performance.

## Reproducibility and evaluation

Use distinct simulated worlds for training, validation, and testing. Keep `episode_ground_truth.csv` and `session_ground_truth.csv` out of model inputs. For T+30/T+60/T+300 checkpoints, include only activity observed by that point in time. See `METHODOLOGY_AND_LIMITATIONS.md` for additional guidance.

## How to share

Publish these source files on a public GitHub repository (GitHub → **New repository** → upload these files → **Commit changes**). Do **not** upload generated multi-million-row CSVs to a normal Git repository. If sharing generated datasets later, use a separate archive or dataset-hosting service with clear versions and metadata.

## License and citation

**No open-source license has been assigned in this package.** Before inviting unrestricted reuse, add an appropriate `LICENSE` file (for example, MIT for code, after confirming ownership and any rights requirements), and identify the repository author(s). You can add a citation file or an archived release DOI later. The dataset, if published, may require a different license from the code.
