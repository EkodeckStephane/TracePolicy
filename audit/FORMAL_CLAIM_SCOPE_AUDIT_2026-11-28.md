# Formal claim and proof scope audit

**Date:** 2026-11-28  
**Artifact reviewed:** `formal/TracePolicy_Formal_Specification.tex`, the 2026-11-26/27 formal-verification report, and the corresponding claim language in the companion manuscript.  
**Decision:** Phase 3 remains **NO-GO**; G2 remains **NOT VERIFIED**.

## Findings

### Finite-set arguments

The abstract sufficiency definition and the elementary finite-set arguments are coherent under the stated fixed background and retention domain. Upward monotonicity follows because retaining a larger core restricts the set of admissible completions. The deletion algorithm preserves sufficiency; after its final pass, every retained unit has a differing-class witness for the one-unit deletion of the final core. Together with upward monotonicity, those single-deletion failures imply inclusion-minimality. The argument proves inclusion-minimality, not minimum cardinality.

No error was found in these set-theoretic proof sketches. This is a local mathematical review of the displayed definitions and arguments, not independent verification of every implementation path or every theorem in the artifact.

### Scope and naming

The guarantee is exact only for the declared finite Boolean intervention space: in-horizon events may be neutralized as position/time-preserving stutters, all explicit rules may be disabled, earlier context and policy contents stay fixed, and replay starts from the API's empty state. “Causal” is therefore an operationally defined, decision-relative term in this work. The manuscript explicitly disclaims physical causation and attack attribution; its terminology should remain consistently qualified wherever the core is called causal or a cause.

The arbitrary-finite-instance existence result and the extraction guarantee are generic consequences of finite-set sufficiency plus an exact decision oracle. The finite-domain model check is useful implementation evidence, but neither item establishes a novel policy-specific theorem. A distinct contribution requires a proved property of the trace/policy semantics that does not reduce to generic abductive explanations or ordinary AXp/minimal-sufficient-set reasoning.

### Remaining proof obligations

1. Independently audit every theorem and proof in the formal artifact against its exact assumptions, including the indexed and incremental evaluator equivalence statements.
2. Trace every public explanation and update path to those assumptions; custom initial state is explicitly outside the current explanation API, while update histories and policy-version transitions require adversarial coverage.
3. Prove selector-reduction completeness for every supported selector and missing/malformed-field behavior, or state and enforce narrower input preconditions.
4. Verify independently that each returned witness satisfies the final retained-core constraints and reproduces the reported class under the bound policy version.
5. Separate theorem validity from implementation evidence, and separate both from scientific novelty. The generated checker covers a finite domain only.
6. Replace or qualify any unbounded use of “causal” that could be read as a physical or interventionally unrestricted causal claim.

## Required follow-up

Keep G2 `NOT VERIFIED` until proof-to-code traceability and the outstanding edge-case audit are complete. Keep G1 `NOT VERIFIED` independently: proving generic correctness does not resolve the collision with policy-change-impact and AXp explanation methods. Keep G4 `NOT VERIFIED`: the current product-subcube criterion is equivalent to joint sufficiency and is not yet a useful structural characterization of policy classes.

This audit does not change the manuscript, formal artifact, algorithm, or experimental data. No new test was added or run for this documentation-only review. Existing CI run `46149459654` completed successfully, including the finite semantic model checker; that result is implementation evidence within its generated domain, not a proof of arbitrary-domain theorems.