# TracePolicy scientific revision roadmap

Baseline: public branch `revision/cose-2026-review`, commit `37221772b808afb429f246b8793edf78e95f2819` (verified against GitHub on 2026-11-26). The manuscript and reviewer package are local companion artifacts, not contained in this code-only GitHub snapshot. The project is therefore at **NO-GO** for an unconditional scientific submission decision.

## Phase 0 — baseline freeze: completed for the reviewed snapshot

- Current branch head matches the local checkout; worktree was clean before the audit artifacts were created.
- Public 71-file publication freeze: zero hash mismatches.
- Repository tests: 67 pass after installing only the two missing temporal-test dependencies into a temporary environment; the unmodified base environment had one skipped test.
- Saved explanation evidence verifier passed for 360 Anchors, 120 FFA, 448 chronological THEIA method outputs, 2,224 independently checked witnesses, and 15 complete live proofs.
- Current author-review PDF/package verification passed in the companion workspace. This is not a fresh clean-clone LaTeX build.
- No raw data or prior result artifacts were overwritten; full campaigns were not rerun.

## Phase 1 — reviewer criticisms: next, highest priority

Re-read the original report and all 18 mapped requests. Create `REVIEWER_CRITICISM_MATRIX.csv`, `REVIEWER_RESOLUTION_REPORT.md`, and `REVIEWER_EVIDENCE_MAP.json`; for each comment, distinguish a manuscript edit, a verified software property, an experiment, and an unresolved limitation. Do not treat the existing response as proof. Resolve the journal-fit gate first: Elsevier's current public Computers & Security page says it has a moratorium on submissions with AI/ML as significant components. The deterministic policy/explanation contribution may or may not fall within that rule; obtain authoritative clarification before investing in journal-specific finalization.

## Phase 2 — SOTA and originality

After the reviewer map, audit closest work from full text, with exact object/guarantee/hypothesis comparisons. First validate the references for CAPTAIN, ORTHRUS, SecTracer, the 2026 causal-access-control work, FFA/MUS-MCS, policy explanation and provenance. Produce the systematic review, collision matrix, lineage and inaccessible-full-text register. Do not claim novelty by absence.

## Phase 3 — formal audit

Audit every definition, algorithm and theorem in the current TeX against executable semantics. Priority question: under what conditions does the union of event-only and rule-only explanations remain jointly sufficient, and how do all alternative minimal kernels behave? Establish counterexamples and any positive characterization before strengthening claims.

## Phase 4 — implementation traceability

Map formal objects to functions, independent verifier, tests and outputs. Audit initial-state restrictions, policy immutability, horizon, relevant-unit filtering, distributed loss/version behavior and certificates. Keep fixes separate from published baseline results until validated.

## Phase 5 — central four-way ablation

Add E-only, R-only, naive union, and exact E+R under one shared oracle and explicit intervention semantics. Enumerate all separated and joint minimal kernels where feasible. Use isolated output directories; preserve prior ablation files. Evaluate union sufficiency in the joint domain and report where it fails, succeeds, or is nonminimal.

## Phase 6 — fair SOTA comparison

Separate native output, adapted output, shared certification and exact minimization for KernelSHAP, LIME, Anchors, FFA and any scientifically eligible formal/provenance comparator. Account for domains, information, budgets, calls, certification and postprocessing.

## Phase 7 — scaling

Reproduce the 18-unit boundary in an isolated run and report exact wall time, memory, evaluations, all failures and timeouts. A SAT/SMT backend is a research task, not an assumed deliverable; implement only after theory and encoding are frozen, then compare all outputs with exhaustive enumeration on small domains.

## Phase 8 — external validation

First audit candidate source data and labels without opening test outcomes. Existing BETH, THEIA, LID-DS and scanned DEDALE evidence is not an untouched independent holdout. Freeze an evaluation only when the identity, timestamp, label unit, split, license and policy-construction route support the estimand. If no suitable holdout exists, retain the narrow scope and report the blocked gate.

## Phase 9 — policy evolution

Create pre-specified realistic add/delete/condition/priority/conflict/regression examples. Compare decision explanations before and after policy changes, differential cores, and methods with equal access to context. Do not infer operator utility without analyst evaluation.

## Phase 10 — distributed validity

Reanalyze existing WSL/VPS runs within their demonstrated bounds; add controlled loss, delay, reorder, duplicate, clock and divergent-version cases only under a frozen protocol. Distinguish integration from IDS efficacy and production scale.

## Phases 11–14 — claim graph, reproduction, manuscript and adversarial review

Update C01–C13 and trace each claim through assumptions, theorem, implementation, tests, data, output and manuscript. Build isolated locked environments, reproduce essential claims without overwriting results, regenerate figures/PDFs, align cover letter and prior-review map, then run four independent adversarial reviews.

## Phase 15 — gate decision

Keep all G0–G15 at `NOT VERIFIED` until the relevant artifacts are examined. Upgrade to `FAIL` where available evidence contradicts a requirement and to `PASS` only with direct evidence. A single `FAIL`/`NOT VERIFIED` means NO-GO. The current journal moratorium ambiguity, novelty, composability and independent validation are immediate gates.

## Phase transition rule

No phase is called complete because it was planned or because a response was drafted. Each phase must record actual commands, files, hashes, results, limits, and its GO/NO-GO decision. Historical output remains immutable; new campaigns use versioned protocols and new output directories.

## Continuation update — 27 November 2026

The public revision branch now includes the expanded retrospective composability sample and paired policy-version replay. At commit `3609cac7ad1277678005d0847fe8b271c3330831`, the GitHub Actions revision workflow completed successfully.

- **Phase 5 — partial.** The initial 120-case sample was supplemented with a fixed-seed sample of 239 alert windows from 120 nonempty workload/scenario strata. All 335 event/rule core unions were sufficient and every case included a union equal to a joint minimal core. This strengthens the evidence that the current Docker policy workload does not show an empirical advantage for joint enumeration. The semantic counterexample remains valid; an external, alert-independent evaluation is outstanding.
- **Phase 9 — partial.** Three fixed edits to the Docker policy changed decisions on 604, 693 and 179 five-event windows. One differing window per edit has per-version core families independently verified. This is paired replay, not a differential explanation. The empty core for the post-removal `Gap` decision makes the limitation explicit: the changed policy element is not identified by explaining that decision alone.
- **Manuscript artifact.** The companion LaTeX source now includes the expanded composability result. MiKTeX failed to rebuild the PDF because it cannot write its user configuration file, including after an initialization attempt. The existing PDF therefore predates that source update; the author archive must not be frozen as submission-ready until the source and PDF are reconciled.

Current decision remains **NO-GO**. The principal outstanding work is a formal differential explanation object with explicit edit interventions, evaluation on independent and realistic policy changes, originality assessment against the closest literature, external validation, and a reproducible manuscript build.
