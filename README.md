# TracePolicy

**TracePolicy** is a reproducible research implementation for **trace--policy causal provenance in explainable intrusion detection**. It evaluates versioned declarative security policies over execution traces, produces intrinsic minimal event--rule explanations for alerts, diagnoses selected policy-quality conditions, and supports reference, indexed, and incremental evaluation paths that share one canonical decision semantics.

Repository: **https://github.com/EkodeckStephane/TracePolicy**

## 1. Context

Intrusion detection increasingly relies on high-volume system, network, and provenance data. Provenance-based IDS can reconstruct attack paths and causal dependencies, while specification- and policy-based IDS provide explicit decision logic. A practical gap appears when these two properties are needed simultaneously: an operational alert should be linked to the trace events and policy elements that actually determine the decision, and any optimization used for streaming evaluation should preserve that same decision semantics.

TracePolicy addresses this gap with a formally specified, versioned trace--policy model. The repository accompanies the study **“Trace--Policy Causal Provenance for Explainable Intrusion Detection: Minimal Explanations and Semantics-Preserving Evaluation”**. The repository contains the reproducibility materials associated with that study and is maintained independently of journal-specific submission metadata.

## 2. Problem

A declarative IDS can explain an alert by listing matching rules, but that list is often larger than the evidence actually required for the decision. Conversely, post-hoc explanation tools can rank features or inputs, yet their output is an empirical explanation of a decision function rather than a theorem-backed proof object derived from the policy semantics itself.

At the systems level, scanning every rule for every event is simple and exact but can become expensive. Indexing and incremental temporal monitors can reduce work, provided that they preserve the reference evaluator’s alert, evidence, explanation, and diagnosis.

The research problem is therefore to connect four requirements in one auditable framework:

1. deterministic trace-aware policy semantics;
2. minimal intrinsic event--rule explanations;
3. policy-quality diagnosis;
4. efficient evaluation with exact semantic preservation.

## 3. Research question

> **Can a declarative intrusion detector produce inclusion-minimal causal trace--policy explanations with formal guarantees while preserving exact alert semantics under indexed and incremental evaluation?**

The repository also studies the operational conditions that shape the answer: trace completeness, policy coverage, index selectivity, alert granularity, and cross-environment policy alignment.

## 4. Proposed solution

TracePolicy evaluates a tuple containing a trace prefix, reconstructed system state, and an immutable policy version.

A policy rule contains a selector, a guard, an effect (`allow` or `deny`), and a priority. At each event:

1. applicable rules are computed;
2. the maximum applicable priority is selected;
3. all rules in that priority stratum are accumulated;
4. the decision class is produced as `NoAlert`, `Violation`, `Conflict`, or `Gap`;
5. gap and same-priority allow/deny conflict follow fail-safe deny semantics.

The same canonical semantics feeds three outputs:

- the alert class and evidence;
- a policy-quality diagnosis;
- an intrinsic minimal causal trace--policy explanation.

### 4.1 Minimal causal explanations

For an alerting decision, the explanatory universe contains bounded trace-event units and policy-rule units. TracePolicy searches for an **inclusion-minimal sufficient core** whose retained units guarantee the same alert class for all admissible neutralizations of the remaining units. The resulting object separates:

- `T_c`: retained trace/event positions;
- `R_c`: retained policy rules;
- background assumptions;
- counterexample witnesses associated with retained units.

The formal development establishes soundness, existence, and inclusion-minimality under the declared intervention domain. See `formal/TracePolicy_Formal_Specification.tex`.

### 4.2 Policy diagnosis

The implementation exposes:

- policy gaps;
- same-priority conflicts;
- shadowing over a bounded context domain;
- redundancy over a bounded context domain.

The controlled mutation campaign uses known injected conditions as an implementation oracle.

### 4.3 Reference, indexed, and incremental evaluation

Three execution paths are provided:

- **reference evaluator**: direct policy scan and canonical semantic oracle;
- **indexed evaluator**: selector-based candidate reduction followed by full guard evaluation;
- **incremental evaluator**: finite-memory temporal monitors and version-aware policy updates.

The implementation and tests compare the optimized paths against the reference evaluator. The retained experiments record zero semantic divergences across the exercised oracle campaigns.

## 5. Research assets and means used

The study combines formal methods, reproducible software experimentation, public cybersecurity datasets, and real security tools.

### Software and environment

- Python 3.11/3.13-compatible research code;
- Docker for controlled execution;
- Suricata 8.0.5 as a network IDS baseline;
- Wazuh 4.14.7 with a running `wazuh-analysisd` manager as a host/rule baseline;
- SHAP 0.50.0;
- LIME from the official `0.2.0.0` Git tag;
- NumPy, pandas, SciPy, scikit-learn, statsmodels, psutil, pytest, requests, and gdown.

The frozen Python package versions used by the retained experiment runner are listed in `requirements.txt`.

### Data sources

1. **Controlled Docker HTTP bench**: deterministic benign and attack-pattern workloads with independent truth records, access logs, and PCAPs.
2. **TON_IoT Modbus**: 31,106 records used with leakage controls. Date/time are excluded; identical four-register vectors are grouped so they cannot cross train/validation/test boundaries.
3. **DARPA Transparent Computing, CADETS E3**: system-provenance data used for trace-aware evaluation. The large official archives are acquired separately and are not committed to GitHub.
4. **ThreaTrace-derived CADETS UUID mapping**: used as an entity/node mapping for compatible node-level attribution. It is kept distinct from the narrative official DARPA E3 ground-truth report.

Acquisition details are in `datasets/DATASETS.md` and `scripts/collect_datasets.py`.

## 6. Main experimental results

The repository intentionally preserves both favorable and boundary-case observations because they define the conditions under which the framework is useful.

### 6.1 Semantic preservation

Across the retained static, update, and DARPA differential-equivalence campaigns:

- **reference vs indexed divergences: 0**;
- **reference vs incremental divergences: 0**.

This empirical evidence complements the formal equivalence arguments.

### 6.2 Explanation analysis and scope

The original comparison contains **32 controlled same-oracle alerts, all with exactly five explanatory units**:

| Method | Mean explanation time | Sufficient-core agreement |
|---|---:|---:|
| Intrinsic TracePolicy | ~0.416 ms | Jaccard = 1.0 |
| SHAP | ~6.25 ms | Jaccard = 1.0 |
| LIME | ~109 ms | Jaccard = 1.0 |

This is a bounded low-dimensional result, not a general runtime ordering. Two additional checks make the operating domain explicit.

**Real Docker alerts.** `experiments/run_rq2_local_lab_explanations.py` selects 100 true-positive alerts already present in the retained Docker workloads (25 per attack scenario). Their explanation universes contain 3--7 units (mean 6.22). Across these cases, SHAP selects the same sufficient core as the exact intrinsic method (mean Jaccard 1.0); mean measured time is ~0.607 ms intrinsic versus ~4.64 ms SHAP.

**Scaling.** `experiments/run_rq2_scaling.py` varies the explanation universe from 5 to 18 units under a fixed same-oracle construction. The exact procedure performs 26 canonical evaluations at 5 units and 196,610 at 18 units. In the retained environment, its median runtime crosses SHAP at approximately 12 units and reaches seconds near the 18-unit ceiling. The current implementation deliberately raises an error above 18 units.

The formal contribution is therefore an exact, auditable explanation semantics with a measured low-dimensional operating regime. The current brute-force implementation has worst-case time `O(m * 2^m * T_eval)`; scalable exact backends such as incremental SAT/SMT are natural implementation extensions of the same definition.

### 6.3 Policy-defect oracle

The controlled mutation corpus contains 120 cases: 30 each for conflict, gap, redundancy, and shadowing. The implementation matched the injected target in **120/120** cases with zero extra flags in this by-construction corpus.

### 6.4 Index selectivity

At policy size `P=500`:

- selective workload: reference ~60.17 µs, indexed ~9.87 µs;
- collision-heavy workload: reference ~228.43 µs, indexed ~278.51 µs.

The result characterizes indexing as **workload-conditional**. Candidate reduction drives the gain; collision-heavy buckets expose candidate-management overhead.

### 6.5 Local Docker bench

Over 30 seeded workloads:

| System | Event-level F1 | Episode-level F1 |
|---|---:|---:|
| TracePolicy | ~0.7248 | ~0.9976 |
| Suricata | ~0.9829 | 1.0000 |
| Wazuh | ~0.5301 | ~0.9981 |

The contrast between event and episode scoring reflects alert granularity in stateful sequence detection.

### 6.6 TON_IoT after leakage controls

With only the four Modbus register features and strict grouped splits:

- Random Forest: mean F1 ~0.5902, AUC-ROC ~0.5098, AUC-PR ~0.5230;
- Isolation Forest: mean F1 ~0.3916, AUC-ROC ~0.5059, AUC-PR ~0.5271.

These values show the limited ranking information present in this restricted feature view after leakage controls.

### 6.7 CADETS policy-quality analysis

The coarse policy’s derived event-link view has high precision with low coverage, while node-level attribution exposes a strong cross-environment policy-alignment boundary. The trace-aware ablation (`phase5b/`) adds temporal expressiveness and produces strong coverage separation in its targeted sensitive-event subspace; that subspace has low prevalence in attack-linked CADETS activity, so the global node-attribution gain remains limited. This experiment is retained as an explicit **policy-quality and expressiveness ablation**.

## 7. Scientific positioning

TracePolicy advances a research intersection formed by four established lines:

- specification-/policy-based intrusion detection;
- provenance-based intrusion detection and attribution;
- formal/abductive and causal explanation;
- rule indexing and streaming evaluation.

The specific contribution is the integration of **versioned trace--policy semantics + inclusion-minimal event--rule cores + policy-quality diagnosis + semantics-preserving indexed/incremental evaluation** in one declarative IDS framework.

The study is intentionally distinguished from:

- CAPTAIN: adaptive, interpretable rule-based provenance IDS;
- ORTHRUS: provenance attribution quality;
- SecTracer: security provenance and root-cause analysis;
- causal explainable access control: minimal causes for authorization decisions;
- vCause: verifiable causality over endpoint provenance.

The bibliography and manuscript provide the full scientific comparison. This repository focuses on the software and reproducibility materials rather than redistributing the article.

## 8. Repository structure

```text
TracePolicy/
├── src/                         # Core trace-policy engine and adapters
├── tests/                       # Semantic/equivalence tests
├── config/                      # Frozen seeds and experiment configuration
├── experiments/                 # Controlled, TON_IoT, local-bench and DARPA experiments
├── scripts/                     # Preflight, dataset acquisition, orchestration, statistics
├── docker/                      # Reproducible runner + Suricata/Wazuh configuration
├── local_lab/                   # Dockerized controlled HTTP bench and retained outputs
├── datasets/
│   ├── DATASETS.md              # Dataset provenance/acquisition notes
│   └── seed/                    # Small frozen seed artifacts where redistribution is permitted
├── results/
│   ├── raw/                     # Retained raw numerical outputs
│   ├── statistics/              # Final statistical analysis
│   ├── summary/                 # Aggregated outputs
│   └── logs/                    # Execution/environment records useful for reproduction
├── formal/                      # Standalone formal specification
├── phase5b/                     # Trace-aware CADETS expressiveness ablation
├── visualization/               # CSV + TikZ/PGFPlots scientific plotting sources
├── requirements.txt
├── requirements-lime.txt
└── docker-compose.local-lab.yml
```

The article PDF/LaTeX source and internal manuscript-audit reports are intentionally absent from this repository.

## 9. Reproducibility procedure

### 9.1 Prerequisites

Recommended host:

- Linux or WSL2;
- Python 3.11+;
- Docker + Docker Compose;
- at least 16 GB RAM recommended for the large CADETS workflow;
- sufficient disk space for the official DARPA E3 archives and extracted JSON segments.

Check Docker:

```bash
docker --version
docker compose version
```

### 9.2 Clone

```bash
git clone https://github.com/EkodeckStephane/TracePolicy.git
cd TracePolicy
```

### 9.3 Python environment

```bash
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\Activate.ps1   # PowerShell
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-lime.txt
```

### 9.4 Obtain datasets

Read `datasets/DATASETS.md`. For CADETS E3, obtain the official files linked from the DARPA Transparent Computing E3 documentation, then use `scripts/collect_datasets.py`. The acquisition script records SHA-256 hashes and validates required filenames. Large DARPA files are intentionally excluded from Git history.

### 9.5 Run semantic tests first

```bash
pytest -q
```

The retained baseline test suite should pass before experimental results are regenerated.

### 9.6 Run components

Useful entry points include:

```bash
python experiments/run_local_core.py
python experiments/run_rq2_explanations.py
python experiments/run_rq2_lime.py
python experiments/run_rq2_stability.py
python experiments/run_rq2_scaling.py --min-units 5 --max-units 18 --repeats 3
python experiments/run_rq2_local_lab_explanations.py
python scripts/run_local_lab.py
python experiments/run_local_lab_tracepolicy.py
python scripts/run_suricata.py
python scripts/run_wazuh.py
python experiments/run_toniot_local.py
python experiments/run_darpa_cadets.py
```

### 9.7 Explanation-scope validation

The exact explainer is intentionally bounded at 18 explanatory units. Run:

```bash
python experiments/run_rq2_scaling.py --min-units 5 --max-units 18 --repeats 3
python experiments/run_rq2_local_lab_explanations.py
```

These commands regenerate `results/raw/rq2_scaling.csv`, `results/summary/rq2_scaling_summary.csv`, `results/raw/rq2_local_lab_explanations.csv`, and `results/summary/rq2_local_lab_explanations_summary.csv`.

### 9.8 Statistical consolidation

```bash
python scripts/compute_phase5_statistics_v2.py
```

This produces bootstrap 95% confidence intervals, paired Wilcoxon tests, Holm correction within comparison families, effect-direction measures, and a distinct deterministic CADETS point estimate so repeated timing runs are not treated as independent detection observations.

## 10. Integrity and provenance

The repository retains frozen hashes and result manifests from the validated campaign. When regenerating data, preserve the original seeds, train/validation/test boundaries, policy configurations, Docker versions/digests, semantic-divergence files, and the distinction between the derived ThreaTrace entity mapping and the narrative official DARPA report.

The 30 retained binary packet captures are distributed as `local_lab/results/pcaps_30runs.tar.xz`; extract that archive in `local_lab/results/` when direct `.pcap` access is required.

## 11. Visualization

`visualization/` contains the data and TikZ/PGFPlots sources used to create scientific plots. Numerical charts read their data from CSV files; values are not manually copied into plots.

## 12. Known scope conditions

TracePolicy is an explicit-policy IDS. Its detection surface follows the observables and semantic coverage encoded in the active policy. The experiments therefore interpret policy quality as a measurable deployment variable. The current exact explanation implementation is intentionally bounded to at most 18 units and exhibits exponential worst-case scaling; the retained experiments expose this boundary directly.

## 13. Security and responsible use

The repository is intended for defensive cybersecurity research, IDS evaluation, formal policy analysis, and reproducibility. The local attack patterns are controlled test scenarios used against the included Docker laboratory. Run experiments only on systems and networks that you own or are explicitly authorized to test.

## 14. Citation

Citation metadata are provided in `CITATION.cff`. Until the journal article receives its final bibliographic metadata, cite the repository and the associated manuscript title.

## 15. Authors

- Nicolas Nkondock Mi Bahanag — University of Yaounde I
- Jacques Narcisse Bayem — University of Yaounde I
- Stéphane Gaël R. Ekodeck — University of Yaounde I; UMMISCO, IRD France Nord; Sorbonne Université
- Serge Alain Ebele — University of Yaounde I; UMMISCO, IRD France Nord; Sorbonne Université
- Roger Atsa Etoundi — University of Yaounde I (corresponding author)

## 16. License

A software license has not been asserted in this repository package. Add the authors' selected license before third-party reuse if broader redistribution rights are intended.
