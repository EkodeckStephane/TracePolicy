# Direct semantic comparison: TracePolicy, versioned-policy replay, and formal explanations

**Checkpoint:** 26 November 2026  
**Repository commit before this memo:** `b6ac4d066da8d3baf338091b1345e09c8ec70b43`  
**Decision:** NO-GO; contribution significance remains unresolved.

## Scope and source basis

This memo compares the actual intervention definition in the current author manuscript (`revision_COSE_2026/manuscript/TracePolicy_COSE.tex`, §§5.1–5.3 and §6) with the full texts of Brucker and Petritsch (2011) and Ignatiev et al. (AIxIA 2020 proceedings, published 2021). It distinguishes the decision object, explanatory variables, guarantee, output, and operation. The comparison identifies semantic overlaps; it does not claim an exhaustive literature search.

Primary sources: [Brucker and Petritsch, IEEE POLICY 2011, DOI 10.1109/POLICY.2011.47](https://doi.org/10.1109/POLICY.2011.47), [full text](https://logicalhacking.com/publications/brucker.ea-framework-2011/brucker.ea-framework-2011.pdf); [Ignatiev et al., AIxIA 2020 proceedings, DOI 10.1007/978-3-030-77091-4_21](https://doi.org/10.1007/978-3-030-77091-4_21), [full text](https://alexeyignatiev.github.io/assets/pdf/inams-aiia20-preprint.pdf).

## Formal mapping to an abductive explanation

For a fixed TracePolicy instance `x`, background `B`, and target class `y = Class(x)`, define a Boolean feature `z_u` for each intervention unit `u ∈ U(x)`. Define a Boolean classifier

`h_{x,B,y}(z) = 1` iff the evaluator on the instance produced by retention assignment `z` returns `y`.

All factual units have value 1 in the observed instance. TracePolicy's condition for a set `E` is therefore

`for every admissible z, if z_u = 1 for every u in E, then h_{x,B,y}(z) = 1`.

An inclusion-minimal TracePolicy core is exactly a subset-minimal set of positive feature literals sufficient for `h_{x,B,y}` at the observed all-retained instance. This is the local abductive-explanation (AXp) pattern in formal XAI. If the admissible assignments are a strict subset of the Boolean cube, the same mapping is a constrained AXp: encode admissibility and fixed background as hard constraints, and the retained factual units as relaxable feature literals. Consequently:

1. Finite existence of a minimal core follows from the finite sufficient-subset family, as in generic abductive minimization.
2. Deletion witnesses certify irredundance of the selected sufficient set; this is the standard subset-minimality witness.
3. The exact guarantee is meaningful for this event/rule intervention domain, but the abstract AXp guarantee and inclusion-minimality are not new by themselves.
4. Ignatiev et al.'s AXp/CXp hitting-set duality is available only after the contrastive target, admissible assignment family, and background constraints are encoded consistently. The current manuscript does not establish a new duality theorem for TracePolicy.

The potentially distinctive element is the semantics assigned to units: ordered temporal event positions and policy-rule units are jointly varied while a concrete decision's background and policy version are fixed. This is a domain-specific formalization and implementation candidate, not yet evidence of a scientifically significant advance. The paper's own statement that generic abduction supplies the guarantee pattern is appropriate; any novelty claim must rest on a useful property of this structured domain, not a relabeling of AXps.

## Direct comparison

| Dimension | TracePolicy | Petritsch–Brucker (2011) | Ignatiev et al. (2021) | Assessment |
|---|---|---|---|---|
| Object evaluated | A concrete observed trace prefix, reconstructed state, target alert class, and policy version | Recorded access request/context associated with the active policy version | A local instance and class prediction of a logical model | Different application objects; TracePolicy's unit semantics are system/security-specific |
| Version handling | Binds the historical decision to one immutable policy version; its current core varies rule units within that version | Stores versions and log context; replays recorded requests against alternative versions and compares decisions | No policy-version semantics | Version binding/replay and cross-version decision comparison predate TracePolicy; current TracePolicy does not explain the *difference* between two versions |
| Variable units | Event positions and rules are jointly retained or neutralized; outside-horizon context is fixed | Request/context values and policy version can be selected or changed for replay/debugging; no jointly minimal temporal-event/rule core identified in the reviewed text | Feature-value literals in a fixed instance | Candidate distinction: mixed event/rule intervention semantics with temporal event units |
| Sufficiency | Every admissible completion retaining the core yields the observed alert class | Re-evaluation and comparison of outcomes; no AXp-style joint core certificate identified | Every feature assignment extending an AXp yields the target class | TracePolicy's guarantee is an instance of formal local sufficiency under its encoded domain |
| Minimality | Inclusion-minimal by deletion, with a counterexample witness for each retained unit | Not the output contract described in the reviewed paper | Subset-minimal AXps; CXps are minimal changes | Generic minimality and witnesses do not establish novelty |
| Output | Event/rule core, sufficient-decision evidence, and per-unit deletion witnesses | Versioned request replay, decision comparison, policy debugging state | AXp/CXp and enumeration algorithms | Distinct output forms; no evidence yet that TracePolicy's form improves an operational task |
| Evaluation evidence | Current samples and a constructed composability witness; no analyst-utility or external frequency estimate for cross-core failures | Framework applications for policy lifecycle/debugging, including version replay | Formal relationships and algorithmic evaluation for XAI models | Evidence targets differ; direct performance ranking is not valid |

## Consequences for the manuscript's claims

1. **Versioning:** describe immutable version binding as a necessary semantic and reproducibility condition. Do not claim version management, replay, or decision comparison as novel.
2. **Formal guarantees:** identify finite existence, inclusion-minimality, and deletion witnesses as established abductive properties instantiated over this intervention domain. A theorem is new only if it proves a nontrivial property specific to TracePolicy's policy/temporal semantics.
3. **Differential version explanation:** the manuscript's current explanation holds a single policy version fixed. It does not provide a minimal explanation of why decisions differ between `P^v` and `P^{v+1}`. The title's “under Versioned Policies” is accurate as scope, but cannot be treated as a claim of differential explanation.
4. **Candidate contribution:** jointly varying observed temporal event positions and rule units for an intrusion decision is the most precise current distinction. Its originality, generality, workload frequency, and practical value remain unresolved.
5. **Composability:** the paired AXp view reframes the four-way ablation in terms of implicants of the induced Boolean target function. The family of sufficient sets is upward-closed by the universal-completion definition, so any union is sufficient exactly when it contains a joint minimal sufficient set; this implication does not require the underlying decision classifier itself to be monotone. The constructed witness demonstrates crossed pairings that contain no such joint core; this is a finite semantic fact, not evidence of a common operational case.

## Gate impact and next evidence

- `G1` (originality): **NOT VERIFIED**. Two important collision families are now mapped, but the topic review and significance argument are incomplete.
- `G3` (joint-domain value): **NOT VERIFIED**. The semantic object differs from replay and generic AXps, while current retrospective data show all observed separate-core unions sufficient.
- `G4` (composability): **PARTIAL / NOT VERIFIED**. The exact Boolean-function mapping clarifies the condition, but it reduces to the AXp/minterm containment criterion; no useful characterization of policy classes or realistic failure rate is established.
- `G7` (versioning): **NOT VERIFIED**. Current work preserves a decision under one selected version; it does not explain a change across versions or demonstrate comparative diagnostic value.

Required next steps: (i) inspect the manuscript's remaining formal-XAI, policy-explanation, and policy-change references for the same mapping; (ii) decide whether to add a truly differential explanation object or remove any implication of such a capability; (iii) derive a policy-structure-specific result that is not merely the generic AXp definition, or narrow the contribution to a validated domain instantiation; and (iv) evaluate prespecified realistic policy changes and the full four-way ablation on an untouched workload.

**Phase decision:** NO-GO. The semantic comparison narrows the defensible claim but does not establish originality or significance.
