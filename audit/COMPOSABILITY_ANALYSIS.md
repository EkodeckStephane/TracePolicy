# Event-only/rule-only composability analysis

**Status:** in progress. The artifact below supplies a checked counterexample to a universal composability claim and a workload-specific ablation. It does not establish novelty.

## Semantics being compared

Let `D_E`, `D_R`, and `D_J` be the event-only, rule-only, and joint intervention domains defined by the implementation. A core is sufficient when every completion of units outside the retained set yields the factual alert class. Inclusion-minimality is checked by testing every one-unit deletion. The naive-union analysis enumerates the Cartesian product of the *complete* event-only and rule-only minimal-core families and tests each union against the full joint domain.

The implementation result is scoped to the declared finite retention domain and the concrete `trace_policy_engine` semantics. It does not establish physical causality.

## Workload results

The retrospective Docker sample contains 120 selected alert cases. There were 168 cross-product unions across all event-only and rule-only core families. All 168 unions were sufficient in the joint domain; all 120 cases had at least one union equal to an exact joint minimal core. The nine existing controlled fixtures generated 11 unions; all were sufficient, and all nine cases had a union equal to a joint minimal core. No sufficient-but-nonminimal union occurred in those workload and fixture samples.

These observations show that the prior sampled evaluation does not demonstrate a practical advantage of joint-domain search over compositing separated cores. The 120 cases are a selected retrospective sample, the fixtures are small, and neither establishes general composability.

## Counterexample in the implemented semantics

The new semantic witness has trace `A, C, B` and two equal-priority rules:

- `DENY_AFTER_A`: deny a current `B` when `A` appears in the three-event window;
- `DENY_AFTER_C`: deny a current `B` when `C` appears in the three-event window.

Both rules are active and both antecedent events are present in the factual instance, so the target is `Violation`.

Exhaustive results:

- E-only minimal cores: `{e:0,e:2}` and `{e:1,e:2}`.
- R-only minimal cores: `{r:DENY_AFTER_A}` and `{r:DENY_AFTER_C}`.
- Joint minimal cores: the matched pairs `{e:0,e:2,r:DENY_AFTER_A}` and `{e:1,e:2,r:DENY_AFTER_C}`.
- Of the four possible separated-core unions, two are sufficient and joint-minimal. The two crossed unions are insufficient: one joint completion disables the matching rule and neutralizes its antecedent, yielding `Gap` instead of `Violation`.

The target-preservation indicator for this witness is exactly
`f(x_A,x_C,x_B,r_A,r_C) = x_B ∧ ((x_A ∧ r_A) ∨ (x_C ∧ r_C))`,
where each Boolean variable records retention of the corresponding event or rule. This expression follows from the two alternative guarded deny rules and was checked against the engine over all 32 assignments. It is monotone in every retention variable, yet crossed separated-core unions fail; monotonicity alone is therefore insufficient to guarantee composition.

This is a direct, executable counterexample to the statement “every union of an event-only minimal core and a rule-only minimal core is jointly sufficient.” It also shows that some separated-core unions can coincide with exact joint cores. The witness establishes an interaction within TracePolicy's declared semantics; its operational frequency and scientific significance remain unknown.

## Exact composability criterion and proof

For any target class `y`, let `f_y(x,z)=1` exactly when the evaluator returns `y` under event-retention vector `x` and rule-retention vector `z`. For separate cores `C_E` and `C_R`, their union is jointly sufficient exactly when
`∀x ⊇ C_E, ∀z ⊇ C_R: f_y(x,z)=1`.
The event-only certificate supplies only `∀x ⊇ C_E: f_y(x,1_R)=1`; the rule-only certificate supplies only `∀z ⊇ C_R: f_y(1_E,z)=1`. These two boundary-face conditions do not imply the product-subcube condition. The equivalence is immediate from the definition of universal sufficiency: the completions of the joint domain containing the union are precisely the Cartesian product of those two supersets. This is an exact criterion for the declared finite semantics, but by itself it is a restatement of sufficiency rather than a novel characterization of a useful policy class.

In the witness, the separate cores `{x_A,x_B}` and `{r_C}` satisfy their respective boundary conditions, while the joint completion `x_A=x_B=r_C=1, x_C=r_A=0` gives `f_y=0`. Exhaustive enumeration over all 32 assignments verifies the failure and the two matched joint cores. No broader necessary-and-sufficient structural condition for classes of policies has been established.

Independent validation: the witness's minimal-core families were cross-checked against full intervention tables built by the separate `revision_explanation_benchmark.independent_table` routine. Every union in both the workload and witness was assessed using that table. The saved failed unions include explicit falsifying assignments and resulting classes.

## Interpretation and research consequence

The defensible theoretical target is a characterization of *which pairings* compose, rather than the blanket claim that joint explanation always beats separated explanation. The product-subcube criterion is exact for individual pairs, but a structurally informative necessary-and-sufficient characterization for policy classes remains open. The witness identifies a failure mechanism: the separated cores can select alternative sufficient branches, while a crossed pairing preserves neither branch when the unselected event and rule units vary jointly.

An empirical novelty claim remains weak: the observed 120 Docker cases and nine fixtures had universal union sufficiency. Further prespecified scenarios and an external, non-selected evaluation are needed to determine whether the interaction occurs in realistic policies. Any manuscript claim must report both facts: the counterexample refutes a universal theorem, while the current sample does not show frequent practical failure.

## Phase decision

**NO-GO for closing the composability and ablation gates.** The four-way ablation is now implemented and executed, and a counterexample exists under the implemented semantics. The required characterization, preregistered external scenarios, realistic policy-version cases, and manuscript-integrated result remain outstanding.
