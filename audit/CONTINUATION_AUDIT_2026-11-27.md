# Continuation audit — 27 November 2026

## Work completed

- Expanded the companion author manuscript's formal specification: temporal `Seen`, `Count`, and ordered-subsequence `Seq` semantics; effective windows; neutral-event treatment; guard composition; missing-value behavior; complete retention assignment space; intervention mapping; and state reconstruction.
- Replaced ambiguous solver terminology with exhaustive decision-oracle search and clarified the inclusion-minimality proof.
- Added an inductive proof of incremental decision equivalence under explicit initial-state, deterministic-transition, available-history, selector-completeness, immutable-policy, and supported-update assumptions. Defined the maximum effective temporal history `H`.
- Audited and corrected the public formal-specification artifact: it had claimed an SAT/SMT backend and compiled monitor updates that the code does not implement. It now describes exhaustive masks (18-unit cap), bounded-window scans, cumulative state, update preconditions, and conditional equivalence. Its bibliography and build instructions are included; its PDF compiles to 17 pages with no unresolved references/citations or out-of-page text.
- Ran the independent finite-domain model checker twice. The second run checked 94,160 policy/trace pairs, 1,401,136 retention assignments, 71,752 alert explanations with witnesses, 94,160 static-index cases, 188,320 incremental-prefix cases, and 948,160 selector-reduction masks. No discrepancy was found.
- Re-ran 68 repository tests; all passed. The frozen protocol verifier reported 71 files and zero mismatches. The saved-evidence verifier independently checked 2,276 witness records. The joint-union verifier reproduced 168/168 Docker and 11/11 fixture unions as sufficient, with two insufficient crossed unions in the constructed witness.
- Executed an expanded, fixed-seed retrospective sample of two eligible true-positive alerts per workload/scenario stratum across the 30 frozen local-lab workloads. It analyzed 239 cases from 120 nonempty strata (2,074 eligible alerts overall). All 335 separate-core union candidates were jointly sufficient; every case had at least one union equal to a joint minimal core; no sufficient union was non-minimal. The case archive records per-stratum eligibility, selection seed, input hashes, and output hashes, which were rechecked. This sample remains conditional on alerts and is not an independent holdout.
- Replayed three fixed policy edits over every five-event window in the same 30 frozen streams without attack-label filtering. Tightening/relaxing the brute-force threshold and removing `D_ADMIN` changed decisions on 604, 693, and 179 windows, respectively. The old/new explanation core families for one deterministic differing window per edit were independently enumerated and agreed in all three pairs. The result demonstrates paired version replay on this local workload, not a differential explanation: the new `Gap` decision after removing `D_ADMIN` has an empty core and does not name the removed rule. See `POLICY_VERSION_DIFFERENTIAL_ANALYSIS.md` and `results/revision/policy_evolution_pairs_v1/`.
- The companion manuscript source was updated with the expanded ablation figures. Its PDF was not rebuilt because MiKTeX cannot write its user configuration (`issues.json`) even after an initialization attempt. The existing PDF does not include the new figures; source and PDF must be reconciled before freezing a submission package.
- Recompiled the companion manuscript (25 PDF pages including its title page; 24 numbered pages). Final packaging verification reports no out-of-page text or unresolved citations; response document covers all 18 reviewer points; cover letter is one page.
- Rebuilt the author archive as `TracePolicy_COSE_author_review_2026-11-27.zip`: 1,964 members; 1,959 manifest entries verified; three submitted-reference files verified; zero CRC errors and zero manifest disagreements. SHA-256: `de475c61c9fe7c04bbedd1c1dcd97e7604e18ef76688a69227a0d71a5aa67e53`.

## Scope and caveats

The model check independently confirms implementation behavior only over its finite generated domain: at most two rules, bounded trace length and value alphabet, empty initial state, and the supported guard forms included by the generator. It is not a proof for arbitrary policies, custom initial states, concurrent or distributed inputs, or all application integrations. The latest manuscript source remains in the companion author-review package; the public repository commit contains the checker and public audit evidence, not the manuscript PDF.

The corrected formal-specification PDF is a separate public technical artifact, not a substitute for the submitted manuscript. Four minor overfull horizontal lines remain in the artifact source, but the PDF geometry check reports no text outside page bounds.

The PDF compiles. A sub-point vertical overfull warning remains on a bibliography page, with no text outside page bounds in the PDF geometry audit. Cross-reference labels still request a rerun; verify log stability before the final submission package.

## Phase and scientific gate status

Phase 3 remains **NO-GO for closure**. The definition gaps and the missing incremental proof have been addressed in the manuscript, and the finite independent semantic audit found no discrepancy. The novelty and structural significance of joint event–rule explanations remain unresolved; composability has only a bounded ablation and a constructed counterexample. No SAT/SMT backend, independent external holdout, analyst utility study, or realistic validated policy-evolution benchmark has been completed. Generalization and journal-specific fit remain NOT VERIFIED. The project-level decision remains **NO-GO**.

The current official Elsevier journal profile states a moratorium on submissions featuring AI or ML as significant components and says submissions applying AI/ML techniques to system security will not be considered. TracePolicy is a rule-based formal explanation framework rather than a learned detector, but explainability/XAI is central to its framing and it evaluates SHAP, LIME, and formal attribution baselines. The scope of the moratorium for this specific manuscript therefore remains **NOT VERIFIED**; the ScienceDirect Guide for Authors link returned HTTP 403 in this audit. This policy question is an independent submission risk and requires a conservative editorial-fit assessment. [Official Computers & Security profile](https://shop.elsevier.com/journals/computers-and-security/0167-4048)

## Next continuation

1. Independently audit every remaining formal theorem and proof against the current implementation, including edge cases outside the finite checker.
2. Develop or reject a nontrivial structural result on joint/separated explanation composition, then complete the prior-art collision analysis before treating the core as novel.
3. Design and freeze an independent four-configuration ablation including realistic operational policy-version scenarios; the existing Docker results are retrospective and alert-conditioned.
4. Add a second exact backend and characterize scaling, or narrow claims to the verified bounded workload.
5. Complete independent external validation, realistic policy-version evaluation, distributed perturbation tests, and artifact reproduction from a clean clone.
6. Reassess journal policy and manuscript, response, and cover letter together after scientific results stabilize.
