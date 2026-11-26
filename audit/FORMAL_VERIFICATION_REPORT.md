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
| Static semantic equivalence | Selector-bucket lookup is complete for the current event, and guards are re-evaluated by the same evaluator. An adversarial policy ordering can make the indexed evaluator return `applicable`/`top` tuples in a different order from the reference scan even though their sets and decision agree. Tuple order is representational; the manuscript must state set equality for rule evidence, or the implementation must introduce a new versioned output-order contract. The frozen code/evidence snapshot was preserved, so no implementation change was applied. | `PARTIALLY RESOLVED` pending clarification of the manuscript's evidence contract and a broader exhaustive index audit |
| Incremental semantic equivalence | The proof is conditional on enough retained history for every active temporal guard, identical cumulative state, selector-complete indexing, immutable policy contents and a supported policy update. The code rejects a horizon expansion after needed history has been discarded. Full-state and custom-initial-state paths remain outside the explanation API's claim. | `PARTIALLY RESOLVED` pending independent transition/update counterexample search |

## Monotonicity argument

For fixed admissible domain `Adm_B`, if `E` is sufficient and `E ⊆ E'`, then every assignment retaining `E'` also retains `E`. Thus the universal condition for `E` implies the condition for `E'`. This argument does not require the decision function itself to be monotone. It depends on the intervention domain and background remaining fixed while comparing candidate cores.

## Implementation correction made

The audit identified this ordering discrepancy with a concrete wildcard/exact selector arrangement. It affects only tuple order: the randomized equivalence test compares applicable/top sets, and the classification and evidence membership remain equal. The source and test files are included in the 71-file frozen publication-protocol manifest; an attempted local correction caused two expected historical-hash mismatches and was reverted. The frozen verifier now passes again. A future change would require a new versioned snapshot and rerunning every dependent experiment; the manuscript can instead make explicit that rule evidence is compared as a set.

## Open formal questions

1. Independently exhaust small policy/trace domains, including conflicting priorities, default rules, empty policies, neutralized current events, wildcard selectors, nested Boolean guards, state atoms, and bounded temporal windows.
2. Verify the full family of generated witnesses against an independently implemented oracle, not only the production evaluator.
3. Establish whether the selector-reduction option preserves the declared intervention family for all supported cases; keep the full-rule universe as the reference definition.
4. Audit supported custom initial states, externally supplied state, and all API preconditions against the paper's exact scope.
5. Derive a structural composability result that says more than the truth-table restatement; separately assess novelty.
6. Check history-expanding updates, state summaries, empty prefixes, and policy versions using independent adversarial cases.

## Phase decision

**NO-GO for closing Phase 3.** The elementary finite-set proofs are sound under the stated assumptions. The output-order discrepancy is now documented and scoped as representational, subject to manuscript clarification. The complete theorem, oracle, state-transition, witness, and composability audits remain open. The local test pass is regression evidence, not a proof of semantic equivalence.
