# Continuation audit — 27 November 2026

## Work completed

- Expanded the companion author manuscript's formal specification: temporal `Seen`, `Count`, and ordered-subsequence `Seq` semantics; effective windows; neutral-event treatment; guard composition; missing-value behavior; complete retention assignment space; intervention mapping; and state reconstruction.
- Replaced ambiguous solver terminology with exhaustive decision-oracle search and clarified the inclusion-minimality proof.
- Added an inductive proof of incremental decision equivalence under explicit initial-state, deterministic-transition, available-history, selector-completeness, immutable-policy, and supported-update assumptions. Defined the maximum effective temporal history `H`.
- Ran the independent finite-domain model checker twice. The second run checked 94,160 policy/trace pairs, 1,401,136 retention assignments, 71,752 alert explanations with witnesses, 94,160 static-index cases, 188,320 incremental-prefix cases, and 948,160 selector-reduction masks. No discrepancy was found.
- Re-ran 68 repository tests; all passed. The frozen protocol verifier reported 71 files and zero mismatches. The saved-evidence verifier independently checked 2,276 witness records. The joint-union verifier reproduced 168/168 Docker and 11/11 fixture unions as sufficient, with two insufficient crossed unions in the constructed witness.
- Recompiled the companion manuscript (25 PDF pages including its title page; 24 numbered pages). Final packaging verification reports no out-of-page text or unresolved citations; response document covers all 18 reviewer points; cover letter is one page.
- Rebuilt the author archive as `TracePolicy_COSE_author_review_2026-11-27.zip`: 1,964 members; 1,959 manifest entries verified; three submitted-reference files verified; zero CRC errors and zero manifest disagreements. SHA-256: `de475c61c9fe7c04bbedd1c1dcd97e7604e18ef76688a69227a0d71a5aa67e53`.

## Scope and caveats

The model check independently confirms implementation behavior only over its finite generated domain: at most two rules, bounded trace length and value alphabet, empty initial state, and the supported guard forms included by the generator. It is not a proof for arbitrary policies, custom initial states, concurrent or distributed inputs, or all application integrations. The latest manuscript source remains in the companion author-review package; the public repository commit contains the checker and public audit evidence, not the manuscript PDF.

The PDF compiles. A sub-point vertical overfull warning remains on a bibliography page, with no text outside page bounds in the PDF geometry audit. Cross-reference labels still request a rerun; verify log stability before the final submission package.

## Phase and scientific gate status

Phase 3 remains **NO-GO for closure**. The definition gaps and the missing incremental proof have been addressed in the manuscript, and the finite independent semantic audit found no discrepancy. The novelty and structural significance of joint event–rule explanations remain unresolved; composability has only a bounded ablation and a constructed counterexample. No SAT/SMT backend, independent external holdout, analyst utility study, or realistic validated policy-evolution benchmark has been completed. Generalization and journal-specific fit remain NOT VERIFIED. The project-level decision remains **NO-GO**.

The current official Elsevier journal profile states a moratorium on submissions featuring AI or ML as significant components and says submissions applying AI/ML techniques to system security will not be considered. TracePolicy is a rule-based formal explanation framework rather than a learned detector, but explainability/XAI is central to its framing and it evaluates SHAP, LIME, and formal attribution baselines. The scope of the moratorium for this specific manuscript therefore remains **NOT VERIFIED**; the ScienceDirect Guide for Authors link returned HTTP 403 in this audit. This policy question is an independent submission risk and requires a conservative editorial-fit assessment. [Official Computers & Security profile](https://shop.elsevier.com/journals/computers-and-security/0167-4048)

## Next continuation

1. Independently audit every remaining formal theorem and proof against the current implementation, including edge cases outside the finite checker.
2. Develop or reject a nontrivial structural result on joint/separated explanation composition, then complete the prior-art collision analysis before treating the core as novel.
3. Execute the frozen four-configuration ablation on predeclared independent and operational policy/version scenarios.
4. Add a second exact backend and characterize scaling, or narrow claims to the verified bounded workload.
5. Complete independent external validation, realistic policy-version evaluation, distributed perturbation tests, and artifact reproduction from a clean clone.
6. Reassess journal policy and manuscript, response, and cover letter together after scientific results stabilize.
