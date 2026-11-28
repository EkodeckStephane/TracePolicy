# TracePolicy scientific revision roadmap

Baseline: public branch `revision/cose-2026-review`; reviewed audit snapshot `08302c304f53afd10b4e40dad120eed03ff6886d` (2026-11-28; CI run `46144093650`, success). The paired-baseline scientific snapshot `c00de286b193d972b1336661a9b464a732dde8eb` passed CI run `46143818651`. The manuscript and reviewer package are local companion artifacts, not contained in this code-only GitHub snapshot. The project remains **NO-GO** for an unconditional scientific submission decision.

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

## Continuation update — 28 November 2026

- **Phase 2 — originality collision expanded.** Full-text review now explicitly records Margrave's ordered old/new policy-outcome pairs over request contexts and generic AXp/CXp foundations. The paired event/edit pilot is formally a constrained AXp over a pair-valued target; this mapping is documented in `audit/DIRECT_BASELINE_MAPPING_MARGRAVE_AXP_2026-11-28.md`. No native Margrave run or novelty claim is made. G1 remains NOT VERIFIED.
- **Phase 9 — candidate distinction narrowed.** The only remaining candidate distinction is the event/edit intervention domain over temporal traces and a local retention certificate. Its practical diagnostic value and policy-specific theoretical contribution remain unproved; G9 remains NOT VERIFIED.
- **Artifacts.** The manuscript, response and cover letter PDFs were rechecked (25/6/1 pages; no out-of-page text; 18 reviewer points; no unresolved citations). The author archive has 1,991 members, 1,986 manifest-covered hashes, zero CRC errors and zero manifest disagreements; SHA-256 `2238f228944a5d27d6c2e8c166a23ecadc173b59a4e550e93bb7e7ee601cb30b`.
- **Generic AXp baseline — completed for the pilot.** A separate minimal-hitting-set enumerator recovers the complete paired explanation family in all three 64-assignment pilot domains. It shares the pilot's evaluator, intervention semantics, and selected windows; it verifies algorithmic equivalence, not evaluator correctness. See `audit/GENERIC_AXP_BASELINE_REPORT.md` and `results/revision/generic_axp_baseline_v1/`.
- **Margrave feasibility — assessed.** The examined native model is request attributes evaluated by two fixed XACML policies; no trace replay, stateful temporal guards, stutter event interventions, or revertible edit coordinate was found. A compiled 64-row truth table would import the pilot oracle outputs and would not be an independent native semantic baseline. See `audit/MARGRAVE_ENCODING_FEASIBILITY_2026-11-28.md`; no native run is claimed.
- **External policy source screen — candidate only.** SigmaHQ has public Git history, official v2.1 rule/correlation specifications, and rule-linked EVTX/JSON regression samples. Commit `ddf1d4f87fd283513ac1dbf7e178c8a4064047df` is screened. DRL 1.1's attribution obligations are documented; sample-specific terms, rule/test coupling, backend-specific temporal correlation semantics, and the TracePolicy adapter remain unresolved. The documented workflow covers rule-associated samples, not differential correlation replay. No dataset or experiment is claimed; see `audit/EXTERNAL_POLICY_BENCHMARK_CANDIDATE_SCREEN_2026-11-28.md`.
- **Immediate next work.** Preserve DRL attribution, inspect sample-specific terms, select and validate a pinned reference engine, and determine whether a useful semantically faithful temporal subset can be executed. Only then freeze a benchmark using unchanged pre-edit samples and prespecified interacting rule changes. Keep Margrave as literature comparator unless the research question specifically concerns finite-relation representation/query cost.

The current decision remains **NO-GO**. Documentation commit `c5bf80623bc58e2d343d9493fd82039750c4e665` passed CI run `46143359791`; the scientific-code snapshot `c6fb027fba1102768015a5dda1bf322bd6cefc34` also passed CI run `46142868690`.

## Continuation update — 27 November 2026

The public revision branch now includes the expanded retrospective composability sample and paired policy-version replay. The campaign commit `3609cac7ad1277678005d0847fe8b271c3330831` passed GitHub Actions run `45973972198`. The latest gap-register update is at `a9a352201d7599ef40fb4039406b19312461dbe0`; CI run `45975477574` also passed.

- **Phase 5 — partial.** The initial 120-case sample was supplemented with a fixed-seed sample of 239 alert windows from 120 nonempty workload/scenario strata. All 335 event/rule core unions were sufficient and every case included a union equal to a joint minimal core. This strengthens the evidence that the current Docker policy workload does not show an empirical advantage for joint enumeration. The semantic counterexample remains valid; an external, alert-independent evaluation is outstanding.
- **Phase 9 — partial.** Three fixed edits to the Docker policy changed decisions on 604, 693 and 179 five-event windows. One differing window per edit has per-version core families independently verified. This is paired replay, not a differential explanation. The empty core for the post-removal `Gap` decision makes the limitation explicit: the changed policy element is not identified by explaining that decision alone.
- **Manuscript artifact.** The companion author package now contains aligned source and PDFs for the manuscript, reviewer response and cover letter. The manuscript PDF has 25 pages (24 numbered); its rendered pages containing the new ablation and paired replay were inspected. The public code repository does not contain the manuscript files. The package is reproducible and its member hashes have been verified; a bibliography vertical-overfull warning remains without visible clipping.

Current decision remains **NO-GO**. The principal outstanding work is a formal differential explanation object with explicit edit interventions, evaluation on independent and realistic policy changes, originality assessment against the closest literature, external validation, and a reproducible manuscript build.

## Continuation update — 28 November 2026: Wazuh candidate screen

The Wazuh v4.14.10-to-v4.14.11 rule diff and the corresponding Attack Data candidates were screened. Rules 2946/2947 concern `usermod` group additions (2947 specifically `sudo`); rule 88104 concerns MariaDB authentication failure. The available Attack Data `usermod` case concerns a root UID change, and the examined Defender logs do not contain Event ID 3002. Defender rule 62149 changes only the interpolated description field, not its level-10 Event ID 3002 alert condition. No compatible external rule/trace pair or engine replay has been established. See `audit/WAZUH_ATTACK_DATA_CANDIDATE_SCREEN_2026-11-28.md` and `audit/CONTINUATION_ADDENDUM_2026-11-28_WAZUH.md`.

The current structured gate snapshot is `audit/FINAL_SCIENTIFIC_GATE_STATUS.json`, updated to repository commit `4733b71799bb45be78ec64814a52498cf43d91bd`. CI run `46147138346` was still in progress when this update was prepared. The samples under `results/revision/external_candidate_screen/` are untracked, isolated screening artifacts and are excluded from the public commit. Overall decision remains **NO-GO**.
