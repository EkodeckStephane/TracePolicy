# TracePolicy — dedicated revision

TracePolicy evaluates versioned declarative policies over ordered observations and produces bounded inclusion-minimal event–rule explanations of alert decisions. This branch contains corrected explanation interventions and expanded reproducibility evidence. The historical release remains identifiable at commit `bd7d10ed6f3ba0b825f3ae4f0f4bc6c07b124797`.

## What changed

- Explanation masks keep older out-of-horizon events fixed; neutralized events are genuine state identities and retain window position.
- The explanatory universe contains all policy rules by default. Exact set sufficiency, inclusion-minimality and alternative causes are measured separately.
- Unsupported policy updates requiring already discarded history are rejected before changing the active version.
- SHAP/LIME delivered-output measurements include prefix certification, minimality checks and counterexample witnesses.
- The corrected comparison covers120 collected alerts from all30 scripted Docker workloads. All outputs of the three original methods are sufficient and minimal on those selected cases.
- Native Anchors now has360 outputs on these identical alerts, and the exact FFA definition adaptation has120. All are independently sufficient and minimal. Sixteen instances have four valid cores, so lower agreement with one intrinsic core is not incorrectness.
- The paired explanation-domain ablation evaluates event-only, rule-only and joint event-rule retention on those same 120 Docker alerts. Every joint minimal core contains both an event and a rule; 16 cases have four valid joint cores. The joint core has median size 2, compared with size 1 in each single-dimension domain. These domains fix different factual context, so this is evidence for a distinct joint certificate, not a size/performance advantage or analyst-utility result. Nine controlled fixtures and one constructed policy-version switch are reported separately.
- BETH adds a one-host process-event replay. Its selected train/validation sequence example yields seven exact event-rule explanations, all on events labelled `evil=0`; it illustrates explanation structure, not attack-detection efficacy.
- LID-DS 2021 CVE-2020-23839 adds a syscall-sequence evaluation on one controlled scenario. The frozen action-only policy alerts in 120/120 attack-containing test recordings and 4/750 normal recordings; results are recording-level, with no attack-onset localization. The predecessor-gated candidate exceeds the validation alert budget and alerts in all 750 normal test recordings. Raw datasets are external and are not bundled.
- Actual chronological THEIA replay preserves nanosecond timestamps and verified process actors across44,408,090events. Frozen training-only policies are evaluated on13,843,613test rows. Two conditional32-case cohorts have448 verified five-method explanation outputs and896 release witnesses; they represent46 unique events from seven processes. All cores contain only current event plus fallback deny. The fixed positive sequence diagnostic has zero occurrences and was not retuned.
- Portable live collector/coordinator roles exercise real instrumented operations, ordering, deduplication, missing records, late records, version binding and checkpoint recovery. A thirty-run Windows/Ubuntu-WSL2 TCP cohort matches all expected statuses: fifteen complete runs match canonical decisions and fifteen injected-loss/lateness/version profiles remain incomplete. All checkpoint replays agree, and fifteen archived-prefix explanation proofs have sixty verified witnesses. A separate single ordered run uses three instances: a Windows workstation, VPS source B and a VPS coordinator. Its three deliberately constructed benign operations are all committed without gaps, duplicates or pending records; maximum arrival lateness is 1.112 s under a 1.5 s budget, and the expected final policy violation is reproduced. This is a distributed integration result, not attack-detection efficacy. Clock drift was not monitored continuously, and VPS hypervisor/zone independence, adversarial ingestion, sustained load and production deployment remain untested.

## Reproduce and inspect

See [REVISION_REPRODUCIBILITY.md](REVISION_REPRODUCIBILITY.md) for exact commands and separate Python3.11 dependency environments. New results are under `results/revision/`; original `results/raw/` outputs remain historical and use different intervention/timing boundaries.

The extended comparison retains full selected traces, all outcomes, actual witnesses and exhaustive mask tables. `python scripts/verify_revision_evidence.py` checks observed validity and witnesses against those tables. Tests and the publication manifest run in the revision CI workflow.

The exact domain-ablation outputs are in `results/revision/joint_ablation_v1/`; run `python experiments/revision_joint_ablation.py` from the repository root to reproduce them from the included synthetic local-lab inputs. The LID-DS code and derived result record are in `experiments/revision_lidds_*.py` and `results/lidds_cve_2020_23839/`. Reproduction requires a separately acquired scenario archive; the result README documents the staged freeze/evaluate/labels/verify process and limitations.

Formal attribution here is an exact adaptation of the membership-frequency definition, not the published anytime solver. Native Anchors output is never repaired; its sampled precision remains distinct from exact certification. Cache backends and NumPy environments differ, so the expanded campaign does not demonstrate timing superiority.

## Scope

Implemented explanations replay a complete supplied prefix from an empty initial state with the default transition. Policy contents must remain immutable, including caller-owned nested values. Frozen dataclasses do not implement deep freezing. The exact backend rejects domains above18 event/rule units.

Indexed incremental decisions require sufficient retained history. Historical explanations additionally require complete-prefix archival/replay. Temporal guards scan retained windows; shared cached temporal summaries are not implemented. Explanation targets are detector decisions under declared interventions, not physical attack causality or analyst usefulness.

The external MAGIC THEIA static projection is exploratory, loses chronology, and inherits upstream label-assisted training filtering. The separate chronological hosted THEIA derivative records acquisition, actor normalization, label identity, chronological split and prospective policy freeze in [its audit README](revision_audit/temporal_external/README.md). The engagement was familiar from static work, so this is cross-representation validation rather than an unseen dataset. Temporal P1 adds522,332false-positive event rows while recovering46REAPr-positive rows; its detection F1 is worse than P0. Explanation correctness does not establish detector improvement or positive predecessor necessity. CADETS P0 was fitted on its own training partition; its held-out results are not transfer of a Docker policy.

## Provenance

`provenance/FROZEN_PUBLICATION_SHA256_PRE_REVISION.txt` preserves the previous publication manifest. The current manifest records the revised executable layer. Historical freezes are not rewritten to imply retrospective preregistration. Old experiment drivers and corrective gates concern their historical campaigns.

External source datasets are acquired separately; virtual environments, editorial correspondence and reviewer reports are not part of the public software bundle. Git commits identify the code snapshot used by a manuscript version.

## Authors and citation

Jacques Narcisse Bayem (corresponding author), Nicolas Nkondock Mi Bahanag, Stéphane Gaël R. Ekodeck, Samson Priso Essawe Ndedi and Marcel Fouda Ndjodo. Author metadata remain in [CITATION.cff](CITATION.cff). This research branch does not imply journal acceptance or a submission made.

The repository has not asserted a new software license in this revision. Third-party components retain their own attribution and terms.
