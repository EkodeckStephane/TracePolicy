# Independent formal-verification audit — preliminary

**Date:** 2026-11-26  
**Scope:** first-pass audit of the explanation definition, minimization guarantees, static index and incremental evaluator, cross-checked against `src/trace_policy_engine.py`. This is not a completed verification of T1–T5 or all supported input states.

## Interpretation and assumptions checked

The target is the factual alert class produced by a finite trace/policy instance. The explanatory universe consists of event positions within a declared horizon and policy rules, with earlier events fixed as background. Event neutralization is a state-preserving stutter that remains at its timestamp/position and matches no selector; rule neutralization disables that rule. Sufficiency quantifies over every admitted assignment that retains the candidate core. The explanation API replays from an empty state with the default transition, and requires policy content to remain immutable during evaluation.

These assumptions make the full-retention assignment reproduce the factual decision. They also fix the comparison context while event/rule units vary. Conclusions below are conditional on this declared intervention model; they do not establish physical causality, attack attribution, or generalization to other monitoring semantics.

## Theorem-by-theorem first pass

| Manuscript result | Audit finding | Status |
|---|---|---|
| Soundness of deletion minimization | The starting universe is sufficient because retaining every unit reconstructs the factual instance. A deletion is committed only if exhaustive checking finds no assignment that changes the target class, so sufficiency is an invariant. The proof depends on the exact oracle and domain used by the implementation. | `IMPLEMENTED BUT NOT VERIFIED` |
| Existence of an inclusion-minimal core | For a finite universe whose full set is sufficient, a finite nonempty family of sufficient subsets has an inclusion-minimal member. A deletion procedure terminating after testing each remaining unit reaches such a member. This establishes existence, not minimum cardinality. | `VERIFIED` at proof-sketch level; implementation still shares the first row's oracle limitation |
| Inclusion-minimality and witnesses | Sufficiency is upward monotone in the retained core: if `E` is sufficient, every superset is sufficient. If each one-unit deletion from final `E` is insufficient, no strict subset can be sufficient; otherwise a one-unit-deletion superset would be sufficient by monotonicity. The witness pass supplies a counterexample for each such deletion. | `IMPLEMENTED BUT NOT VERIFIED` |
| Static semantic equivalence | Selector-bucket lookup is complete for the current event, and guards are re-evaluated by the same evaluator. An adversarial policy ordering can make the indexed evaluator return `applicable`/`top` tuples in a different order from the reference scan even though their sets and decision agree. The companion manuscript now defines rule evidence extensionally as sets, so presentation order is outside the equivalence claim. The independent finite-domain model check found no class or index discrepancies within its generated domain. | `PARTIALLY RESOLVED` pending proof or broader coverage for arbitrary supported policies and selector forms |
| Incremental semantic equivalence | The companion manuscript now supplies an induction under adequate history, identical initial state and deterministic transition, selector-complete indexing, immutable policy contents and supported updates. Horizon expansion without retained history is rejected before state changes. The independent finite-domain checker found no discrepancy across 188,320 prefix comparisons. Full-state and custom-initial-state paths remain outside the explanation API's claim. | `PARTIALLY RESOLVED` pending proof/code audit for every supported update path and custom state interfaces outside the claimed API |

## Monotonicity argument

For fixed admissible domain `Adm_B`, if `E` is sufficient and `E ⊆ E'`, then every assignment retaining `E'` also retains `E`. Thus the universal condition for `E` implies the condition for `E'`. This argument does not require the decision function itself to be monotone. It depends on the intervention domain and background remaining fixed while comparing candidate cores.

## Implementation correction made

The audit identified an ordering discrepancy with a concrete wildcard/exact selector arrangement. It affects presentation order, not applicable/top membership or the decision. The source and test files are included in the 71-file frozen publication-protocol manifest; an attempted local correction caused two expected historical-hash mismatches and was reverted. The frozen verifier now passes again. The companion manuscript explicitly compares rule evidence extensionally as sets, matching the implemented contract. The independent generated model check further covers the finite selector/policy domain listed below.

## Open formal questions

1. Extend independent policy/trace generation to larger policy sets, all supported comparison types and input values, and adversarial update sequences.
2. Extend independent witness checks beyond the current 71,752 certified alerts and cover every public explanation API mode.
3. Establish selector-reduction validity for every supported selector form and malformed/missing event field; retain the full-rule universe as the reference definition.
4. Audit custom initial states, externally supplied state, and all API preconditions; keep them out of manuscript claims unless verified.
5. Derive a structural composability result that says more than the truth-table restatement; separately assess novelty.
6. Extend checks for history-expanding updates, state summaries, empty prefixes, and policy versions using independent adversarial cases.

## Phase decision

**NO-GO for closing Phase 3.** The elementary finite-set proofs are sound under the stated assumptions. The output-order discrepancy is now documented and scoped as representational, subject to manuscript clarification. The complete theorem, oracle, state-transition, witness, and composability audits remain open. The local test pass is regression evidence, not a proof of semantic equivalence.

## Independent finite-domain model check — 2026-11-27

An independently written executable model was added at `scripts/independent_semantics_modelcheck.py`. It implements transitions, guards, selectors, priorities, and classification separately from the production evaluator; expected outcomes do not call the production classifier, guard, transition, or `_class_under_mask` functions. The saved result is `audit/independent_semantics_modelcheck_2026-11-26.json` (the filename records the run artifact's original date).

The exhaustive generated domain contains 1,177 policies built from 48 rule forms with at most two rules; 80 traces (the complete length-one/two event cube over two actions, resources, and subjects, plus eight length-three temporal traces); and every event/rule retention mask. It checked 94,160 policy/trace pairs, 1,401,136 retention assignments, and 71,752 alert explanations with independent sufficiency and deletion witnesses. It also compared 94,160 static-index cases, 188,320 incremental-prefix cases, and 948,160 selector-reduction masks against the full-rule reference. No discrepancy was found.

This is strong finite-domain evidence for the tested semantics and selector reduction. It is not a proof over arbitrary policies, unbounded traces, every supported guard value/type, custom initial states, concurrent updates, distributed inputs, or all generated explanation APIs. The older unresolved-order statement above is clarified by the manuscript's explicit extensional rule-set contract; public implementation output ordering remains a presentation detail and is not part of the decision-equivalence theorem.

The manuscript now specifies the executable `Seen`, `Count`, and ordered-subsequence `Seq` semantics, neutral-event behavior, guard composition, comparison operators, retention assignment space, state reconstruction, and the intervention map. It also replaces the ambiguous solver-language with exhaustive decision-oracle search and gives an explicit proof of the incremental-equivalence theorem under its stated history and update assumptions. These are manuscript corrections; they do not close the independent theorem-proof, composability-novelty, or generalization questions.

**Updated phase decision: NO-GO for closing Phase 3.** The finite generated audit passed without discrepancies, but the remaining theoretical novelty and proof obligations are substantive and the validation scope remains bounded.

## Formal artifact alignment audit — 2026-11-27

The public `formal/TracePolicy_Formal_Specification.tex` previously described an SAT/SMT extraction backend and cached finite-memory temporal monitors. Both descriptions exceeded the current implementation: explanation checks enumerate Boolean assignments with an 18-unit cap, and incremental guards scan a retained event buffer while state is cumulative. The document also left the admissible retention assignments implicit and described unsupported input/operator details.

The artifact now states the implemented full Boolean retention domain, empty-state explanation API, guard operators and stutter behavior; replaces SAT/SMT pseudocode by exhaustive decision-oracle enumeration; specifies the retained-window invariant, update preconditions, and incremental proof; and marks unverified paths and unimplemented solver scaling explicitly. Its bibliography is bundled and its build recipe is in the README. The formal source compiled to 17 pages with no undefined citations/references and no PDF text outside page bounds. Four minor overfull horizontal lines remain (maximum 15.24 pt in a signature/table paragraph); they are visible in the rendered PDF and do not move text outside the page geometry.

This documentation correction does not add an implementation backend or broader experimental validation. The code remains bounded to exhaustive explanation domains of at most 18 units; the theoretical results remain conditional on their assumptions and the finite independent checker scope.
