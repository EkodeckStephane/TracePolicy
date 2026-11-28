# Restricted policy-class characterization of separated-core composition

**Status:** verified finite family; scientific novelty and operational utility remain unestablished.

## Policy family

Fix `n >= 2` distinct antecedent event positions `A_1,...,A_n`, one shared current event `B`, and `n` equal-priority deny rules. Rule `R_i` selects `B` and fires when `A_i` appears in the fixed observation horizon. There are no competing rules or other trace events. Let `x_B`, `x_i`, and `r_i` denote retention of `B`, antecedent `A_i`, and rule `R_i`.

Under the implemented evaluator, the target class is `Violation` exactly when

`f(x,r) = x_B AND OR_i (x_i AND r_i)`.

Each disjunct is one independently guarded event-rule path to the same decision.

## Proposition

For this family, the complete inclusion-minimal event-only cores are
`E_i = {e:B, e:A_i}`, the complete rule-only cores are `R_i = {r:R_i}`, and the complete joint cores are `J_i = {e:B, e:A_i, r:R_i}` for `i=1,...,n`.

For every pair `(E_i,R_j)`, the union is sufficient in the joint intervention domain exactly when `i=j`. A matched union equals `J_i`. For a crossed pair `i != j`, retain `B`, `A_i`, and `R_j`, while neutralizing `A_j` and disabling `R_i` and all other rules; the resulting class is `Gap`. Therefore exactly `n` of the `n^2` separated-core unions are sufficient, and the crossed-union failure fraction is `1 - 1/n`.

### Proof

When the rules are fixed, preserving `B` and any one antecedent `A_i` guarantees the target; removing either permits a completion with target `Gap`. Hence the event-only minimal cores are precisely the `E_i`. With all events fixed, any single retained rule `R_i` guarantees the target and is necessary, giving the singleton rule-only cores. Jointly, at least one complete pair `(A_i,R_i)` and `B` must remain, so the minimal joint cores are precisely the `J_i`.

If `i=j`, the union retains one complete disjunct and is sufficient. If `i != j`, the stated completion retains the selected literals of the crossed union but disables every complete disjunct, so it yields `Gap`. This proves the pair criterion and count.

## Executable verification

`experiments/revision_composability_family.py` constructs the family in the reference engine and checks the closed-form truth table, all three core families, and every separated-core union using exhaustive intervention tables. The committed summary covers `n=2,3,4,5`: 32, 128, 512, and 2,048 joint assignments, respectively. The observed sufficient-union counts are 2/4, 3/9, 4/16, and 5/25. The CI workflow reruns the script and rewrites the deterministic result at `results/revision/composability_family_v1/summary.json`.

## Scope and scientific assessment

This proves a parameterized counterexample family in one restricted, executable policy class. The Boolean form is a monotone DNF; the explanation and core properties are adjacent to generic AXp/prime-implicant reasoning. The family is constructed, and its failure fraction is not an estimate for operational policies. The Docker alert samples still have sufficient unions in all 335 tested pairings, and no analyst-utility or independent frequency study exists. This result strengthens the formal boundary for the implementation while leaving the novelty and practical-value gates open.
