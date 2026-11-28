# Margrave encoding feasibility for TracePolicy's paired event/edit pilot

**Date:** 2026-11-28  
**Decision:** no semantics-preserving native benchmark is currently justified; direct semantic comparison remains valid.

## Question

Can the six-unit paired pilot be run through Margrave as a fair native baseline, rather than compared only at the level of the explanation object and prior-art output?

## Evidence consulted

- Fisler et al., *Verification and Change-Impact Analysis of Access-Control Policies*, ICSE 2005, full text: <https://web.cs.wpi.edu/~kfisler/Pubs/icse05.pdf> (especially Sections 2, 4, and 6; DOI `10.1145/1062455.1062502`).
- Margrave's Brown University change-analysis tutorial: <https://cs.brown.edu/research/plt/software/margrave/tutorial/change/index.html>.
- TracePolicy's executable semantics in `src/trace_policy_engine.py`, especially `Event.stutter_like`, `transition`, `derive_state`, `Guard.eval`, `classify_from_rules`, and `reference_eval`.
- The paired pilot in `experiments/revision_policy_differential.py` and its finite-domain results.

## Semantic comparison

| Requirement of the pilot | Native Margrave support found in the examined sources | Consequence |
|---|---|---|
| Compare an old and a new policy | Yes: Margrave compares two XACML policies and represents old/new result pairs over requests. | Direct prior-art overlap for semantic differencing is established. |
| Treat input as a time-ordered event trace | No trace or replay object appears in the policy/request model. Requests consist of attributes; policy rules produce a result for that request. | A trace must be compiled into attributes or its temporal semantics must be implemented outside Margrave. |
| Evaluate `Seen`, bounded `Count`, `Seq`, and monitor state after event neutralization | The paper describes a restricted XACML subset, excludes complex conditionals, and does not define sequential state updates or event stutter semantics. | Directly loading the TracePolicy policy would change or omit the tested semantics. |
| Intervene on each of five event positions | Not as native trace-position interventions. An attribute encoding could carry five keep/drop bits, but Margrave would still need the correct temporal replay function. | Encoding only the bits is insufficient; compiling the evaluator into a request-to-decision relation moves the semantics outside Margrave. |
| Intervene on retaining or reverting a policy edit while evaluating both branches | Margrave compares two fixed policies per comparison. The sources do not describe an edit-presence variable that dynamically selects/reverts one policy branch within the same comparison. | Separate fixed comparisons do not reproduce the paired pilot's sixth intervention coordinate. A wrapper can add it only by compiling the branch-selection semantics. |
| Return subset-minimal retained event/edit units plus deletion witnesses | Margrave returns/query-enables regions of requests grouped by old/new outcomes. No local minimal-retention explanation or per-unit deletion certificate is specified. | Additional generic AXp/hitting-set post-processing is required; the generic baseline already tests that output contract on the frozen pilot tables. |

## What can be encoded, and what that would mean

For a fixed six-unit domain, a translator could precompute the 64 old/new output pairs and represent that truth table as a Boolean policy over six request attributes. If the restricted XACML fragment admits the required finite Boolean construction, Margrave could then expose regions for each output pair. Such an encoding would preserve the already-computed finite relation, but it would not independently execute TracePolicy's temporal policy semantics: its truth table would be the input to the encoding. Extracting minimal retained literals would still require a separate AXp procedure.

That is a possible format-conversion or decision-diagram check, not a fair native Margrave evaluation of policy semantics. It risks circularly feeding TracePolicy's answers into the comparator. No Margrave installation or native execution was performed. The current evidence therefore does not justify claiming an implementation comparison or a Margrave performance baseline.

## Conclusion and next action

The semantic boundary is sufficiently clear to decline a native benchmark for the existing pilot unless an independently specified, semantics-preserving translator is developed. Retain Margrave as direct prior art for paired policy outcomes and changed-context regions. Retain generic AXp as the fair exact baseline for local minimal event/edit explanations.

To justify a future Margrave execution, a translator would need a separate specification, a proof of decision equivalence for all 64 assignments on each case, and verification that the comparison does not encode precomputed target outputs as the policy itself. Even then, it would compare finite relation representations and query costs, not establish distinct diagnostic utility. Independent realistic policy changes and an explicit diagnostic task remain necessary for that question.

**Gate effect:** G1 remains NOT VERIFIED; G5 remains NOT VERIFIED pending broader baseline fairness; G9 remains NOT VERIFIED. This feasibility analysis narrows the next experiment, it does not resolve novelty or generalization.
