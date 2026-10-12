# TracePolicy — dedicated revision

TracePolicy evaluates versioned declarative policies over ordered observations and produces bounded inclusion-minimal event–rule explanations of alert decisions. This branch contains corrected explanation interventions and expanded reproducibility evidence. The historical release remains identifiable at commit `bd7d10ed6f3ba0b825f3ae4f0f4bc6c07b124797`.

## What changed

- Explanation masks keep older out-of-horizon events fixed; neutralized events are genuine state identities and retain window position.
- The explanatory universe contains all policy rules by default. Exact set sufficiency, inclusion-minimality and alternative causes are measured separately.
- Unsupported policy updates requiring already discarded history are rejected before changing the active version.
- SHAP/LIME delivered-output measurements include prefix certification, minimality checks and counterexample witnesses.
- The corrected comparison covers120 collected alerts from all30 scripted Docker workloads. All outputs of the three original methods are sufficient and minimal on those selected cases.
- Native Anchors now has360 outputs on these identical alerts, and the exact FFA definition adaptation has120. All are independently sufficient and minimal. Sixteen instances have four valid cores, so lower agreement with one intrinsic core is not incorrectness.
- Portable live collector/coordinator roles exercise real instrumented operations, ordering, deduplication, missing records, late records, version binding and checkpoint recovery. A thirty-run Windows/Ubuntu-WSL2 TCP cohort matches all expected statuses: fifteen complete runs match canonical decisions and fifteen injected-loss/lateness/version profiles remain incomplete. All checkpoint replays agree, and fifteen archived-prefix explanation proofs have sixty verified witnesses. This uses two OS environments on one physical machine; separate physical hosts are not demonstrated.

## Reproduce and inspect

See [REVISION_REPRODUCIBILITY.md](REVISION_REPRODUCIBILITY.md) for exact commands and separate Python3.11 dependency environments. New results are under `results/revision/`; original `results/raw/` outputs remain historical and use different intervention/timing boundaries.

The extended comparison retains full selected traces, all outcomes, actual witnesses and exhaustive mask tables. `python scripts/verify_revision_evidence.py` checks observed validity and witnesses against those tables. Tests and the publication manifest run in the revision CI workflow.

Formal attribution here is an exact adaptation of the membership-frequency definition, not the published anytime solver. Native Anchors output is never repaired; its sampled precision remains distinct from exact certification. Cache backends and NumPy environments differ, so the expanded campaign does not demonstrate timing superiority.

## Scope

Implemented explanations replay a complete supplied prefix from an empty initial state with the default transition. Policy contents must remain immutable, including caller-owned nested values. Frozen dataclasses do not implement deep freezing. The exact backend rejects domains above18 event/rule units.

Indexed incremental decisions require sufficient retained history. Historical explanations additionally require complete-prefix archival/replay. Temporal guards scan retained windows; shared cached temporal summaries are not implemented. Explanation targets are detector decisions under declared interventions, not physical attack causality or analyst usefulness.

The external MAGIC THEIA static projection is exploratory, loses chronology, and inherits upstream label-assisted training filtering. It does not replace chronological validation. Any further external campaign records its own acquisition, label provenance, chronological split and prospective policy freeze separately. CADETS P0 was fitted on its own training partition; its held-out results are not transfer of a Docker policy.

## Provenance

`provenance/FROZEN_PUBLICATION_SHA256_PRE_REVISION.txt` preserves the previous publication manifest. The current manifest records the revised executable layer. Historical freezes are not rewritten to imply retrospective preregistration. Old experiment drivers and corrective gates concern their historical campaigns.

External source datasets are acquired separately; virtual environments, editorial correspondence and reviewer reports are not part of the public software bundle. Git commits identify the code snapshot used by a manuscript version.

## Authors and citation

Jacques Narcisse Bayem (corresponding author), Nicolas Nkondock Mi Bahanag, Stéphane Gaël R. Ekodeck, Samson Priso Essawe Ndedi and Marcel Fouda Ndjodo. Author metadata remain in [CITATION.cff](CITATION.cff). This research branch does not imply journal acceptance or a submission made.

The repository has not asserted a new software license in this revision. Third-party components retain their own attribution and terms.
