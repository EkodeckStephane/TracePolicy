# Paired event/edit explanation pilot

**Status: exploratory; formal object demonstrated on three finite examples, originality and usefulness unresolved.**

## Question

Can a minimal explanation of a policy-induced decision change identify both the observed events and the policy edit needed to preserve the exact before/after decision pair? This pilot follows the open item in `POLICY_VERSION_DIFFERENTIAL_ANALYSIS.md`. It is motivated by the removal example where the new-version ordinary explanation is empty.

## Definition used in the pilot

Let `P0` be the original policy, `P1` the policy after a fixed, atomic edit, and `τ` the observed event suffix. Let `U_E` contain the event positions in `τ`, and let `U_Δ` contain the edit unit that transforms `P0` into `P1`. For any retention assignment:

- An event retained in `U_E` remains factual. A neutralized event is replaced by a state-preserving stutter at the same position in both policy branches.
- A retained edit applies the specified edit to the new-policy branch. A neutralized edit reverts that branch to `P0`.
- The target is the exact ordered pair `y* = (class(P0, τ), class(P1, τ))`.
- A subset `S ⊆ U_E ∪ U_Δ` is sufficient if every admissible completion retaining `S` returns exactly `y*`. It is inclusion-minimal if no strict subset is sufficient.
- For every retained unit, the artifact stores a deletion witness: a completion retaining the other core units for which the ordered pair changes.

This is a local explanation of one paired policy comparison. It is distinct from an explanation of either version's decision alone and from the semantic region of requests whose outcome differs between policies. It also reduces to a constrained AXp over a pair-valued function, so the definition alone is not a novelty result.

## Frozen pilot and results

The same three policy edits and first-differing-window selection from `revision_policy_evolution.py` were used. Each representative case has five event units and one atomic edit unit, giving 64 intervention assignments. The paired truth table is enumerated, and all minimal sufficient sets are derived by subset enumeration. A separate verification script regenerates each finite table and checks the complete minimal-core family and all deletion witnesses. The verifier uses the same reference decision evaluator and policy-edit constructor; it independently checks finite enumeration and certificates, not the semantics implementation itself.

| Edit | Factual pair (old, updated) | Minimal paired explanation | Contrast with ordinary per-version explanations |
|---|---|---|---|
| `D_BRUTEFORCE` threshold 4→3 | `(NoAlert, Violation)` | `{e:2, e:3, e:4, d:D_BRUTEFORCE.count_threshold}` | Replaces the rule-presence unit with the actual threshold edit in the paired account. |
| `D_BRUTEFORCE` threshold 4→5 | `(Violation, NoAlert)` | `{e:1, e:2, e:3, e:4, d:D_BRUTEFORCE.count_threshold}` | Includes the policy edit and the four event positions needed to preserve this exact reversal. |
| Remove `D_ADMIN` | `(Violation, Gap)` | `{e:4, d:D_ADMIN.presence}` | Identifies the removed rule edit even though the ordinary new-version `Gap` core is empty. |

Each core has a stored deletion witness for every event and edit unit. The verification artifact reports three matching complete families and valid witnesses. Inputs, experiment source, outputs, hashes, and verification summary are under `results/revision/policy_evolution_differential_v1/`.

## Collision analysis and limits

Margrave already computes policy-version change regions over request attributes, and versioned replay already compares decisions under alternative policies. The candidate difference here is a minimal local certificate over a concrete temporal trace plus an explicit atomic policy edit. Since the pair-valued target can be encoded as a finite output label, generic abductive explanation theory may cover the construction. The evidence does not yet establish a new theorem, a useful advantage over Margrave or AXp, or improved policy debugging.

Only the first differing window for each of three edits was analyzed. The policies are one local-lab policy, the trace source is the same retrospective Docker corpus, and the windows are selected because their decisions differ. No independent policy family, untouched holdout, native Margrave comparison, analyst evaluation, or multi-edit interaction is covered. The event/edit interventions and the atomic edit granularity need further semantics for interacting edits, state initialization, and distributed logs.

## Decision

This pilot strengthens the formal feasibility of a paired explanation and supplies a concrete case where it carries edit information that single-version cores omit. It does **not** close G1, G3, G5, G8, or G9. The novelty gate remains NOT VERIFIED pending a theorem or empirically validated property beyond the generic AXp mapping, a fair direct baseline, and independent realistic policy-change evaluation. Do not add the pilot as a principal manuscript contribution until those conditions are addressed; do not describe three examples as generalization.
