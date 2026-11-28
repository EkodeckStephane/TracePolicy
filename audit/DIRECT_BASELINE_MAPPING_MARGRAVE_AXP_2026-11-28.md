# Direct baseline mapping: Margrave change analysis and generic AXp

**Status: analytical mapping from primary full texts; no native Margrave run is claimed.**

## Question

Does the paired event/edit pilot introduce a new output or explanation principle beyond policy change-impact analysis and formal abductive explanations?

## Primary-source facts

Fisler et al.'s Margrave consumes two policy versions and summarizes their semantic differences over requests. Its change-analysis decision diagram has one terminal for each ordered pair of policy outcomes. The paper explains that change analysis identifies the requests yielding different answers under the two policies and allows users to query the change representation. These are direct antecedents for (i) pair-valued old/new policy outcomes and (ii) exhaustive regions of contexts associated with each outcome pair.

Ignatiev et al. define a local AXp as a subset-minimal set of factual feature literals sufficient for the target prediction under every completion of the remaining features. Their paper also establishes the AXp/CXp minimal-hitting-set duality. Therefore subset-minimal sufficiency for a finite pair-valued target is an instance of generic formal AXp theory after encoding the target pair as one class and admissibility constraints as background.

Sources: Fisler et al. (ICSE 2005), DOI `10.1145/1062455.1062502`, author-hosted full text `https://web.cs.wpi.edu/~kfisler/Pubs/icse05.pdf`; Ignatiev et al. (AIxIA 2020, published 2021), DOI `10.1007/978-3-030-77091-4_21`, author-hosted full text `https://alexeyignatiev.github.io/assets/pdf/inams-kr21-ea.pdf`.

## Formal correspondence

For fixed policies `P0` and `P1`, Margrave represents a function of request context `x` whose value is the ordered pair `(P0(x), P1(x))`. Its Cmtbdd has terminals for the possible pairs of policy outcomes. It reports the regions of request contexts associated with those pairs; it does not define its principal output as a subset-minimal set of trace events and rule edits.

The TracePolicy pilot instead defines a finite admissible intervention space `A` over event-retention units and an atomic reversible edit unit. Each assignment `a in A` determines a common transformed trace and the policy selected for the updated branch. The evaluator is a function `F(a) = (class_old(a), class_updated(a))`. For the factual assignment `a*`, it explains the target pair `y* = F(a*)` by a subset-minimal set of retained factual units that forces `F(a) = y*` for every admissible completion retaining those units.

Let `g_y(a) = 1` exactly when `F(a) = y*`. The pilot explanation is a prime implicant of `g_y` at `a*`, relative to admissibility constraints. This is a constrained AXp over a pair-valued function. Replacing the pair by a single class label does not alter the generic AXp definition or its minimal-hitting-set foundations.

**Proposition (constrained-AXp reduction).** Let the finite intervention universe be `U`, let `A` be the declared admissible assignments, let `a*` be the factual all-retained assignment, and let `F: A -> Y` return the ordered pair of policy-branch outputs. A set `S subseteq U` is a sufficient retention explanation for `y* = F(a*)` exactly when `forall a in A`, if `a_i = 1` for every `i in S`, then `g_y(a) = 1`, where `g_y(a) = 1 iff F(a) = y*`. It is inclusion-minimal exactly when no strict subset has that property. For each `i in S`, a deletion witness is an admissible assignment with `a_j = 1` for every `j in S minus {i}` and `F(a) != y*`.

**Proof.** By definition, retaining `S` restricts completions to assignments in `A` whose coordinates in `S` equal their factual value 1. Universal preservation of `y*` on that restricted set is precisely the implication defining `g_y` above. Subset-minimality is the same set-minimality condition on sufficient feature literals. Negating sufficiency after removing `i` yields an admissible counterassignment, which is exactly the stated deletion witness. No monotonicity assumption on `F` is needed; only the usual upward closure of sufficient retained sets follows from universal quantification over completions. This is a reduction to established AXp semantics, not a TracePolicy theorem of novelty.

## What the overlap establishes

| Aspect | Margrave | Generic AXp | TracePolicy paired pilot |
|---|---|---|---|
| Main input | Two access-control policies and request attributes | A model/classifier, factual instance, target output | Two policy branches, concrete temporal trace, event/edit intervention domain |
| Output target | Ordered pair of policy outcomes | One target class, including an encoded pair label | Exact ordered pair of alert classes |
| Variable space | Request/context attributes | Features or literals under stated constraints | Event positions plus policy-edit units; neutralization uses a shared state-preserving stutter |
| Main result | Queryable semantic regions of requests with each old/new outcome pair | Subset-minimal sufficient literal sets; duality with contrastive sets | Subset-minimal retained event/edit sets with deletion witnesses |
| Established overlap | Pair-valued version comparison and change-impact regions | Pair-valued local sufficiency/minimality after encoding | Domain-specific intervention semantics and implementation candidate |

The pair-valued target and the minimal-sufficiency principle are not novel by themselves. The candidate distinction is the particular joint intervention semantics over temporal trace positions and reversible policy edits, together with a local certificate. That distinction is a domain-specific formalization until it yields a new policy-class theorem, a verifiably useful capability, or a measured diagnostic advantage.

## Limits of the comparison

The Margrave paper studies XACML policies and request attributes. The pilot's temporal state transitions, stutter neutralization, explicit rule-edit intervention, and cross-branch shared trace are not automatically represented by the Margrave input language or tool interface. No source examined here establishes that a native Margrave installation can ingest this TracePolicy model directly. Thus the literature comparison is direct at the level of output semantics and analysis objective, but not yet an implementation benchmark.

The generic AXp comparison is stronger semantically: if a candidate AXp solver receives exactly the pilot's admissible assignment predicate and oracle `F`, its explanation family must match the pilot's complete minimal family. A fair runtime comparison would still require implementing this encoding and aligning solver budgets, certificate checking, and admissible-domain semantics. It would measure algorithms for the same formal problem, not establish a different explanation principle.

## Required fair comparison

1. Freeze the same policies, traces, event neutralization, edit units, factual assignment, admissible completion constraints, and ordered-pair target for every method.
2. Treat the exact evaluator truth table as the common oracle on the six-unit pilot cases; enumerate the full family of prime implicants/AXps and compare it with every TracePolicy core, not one selected core.
3. Report native outputs separately from outputs after a shared certification and minimization procedure. Attribute sufficiency, minimality, and deletion witnesses to the operation that actually establishes them.
4. For Margrave, first document whether the policy/trace semantics can be encoded without changing the question. If it cannot, report a semantic comparison and the incompatible constructs; do not claim an experimental baseline. If an encoding is feasible, compare its old/new outcome regions with TracePolicy's local explanation and state clearly which output conversion is shared post-processing.
5. Extend the comparison to prespecified independent policy families and realistic edits before drawing claims about policy-debugging utility.

## Decision impact

This mapping strengthens the collision finding and keeps G1 and G9 **NOT VERIFIED**. It narrows the candidate contribution to event/edit intervention semantics and a local certificate. The three-window pilot does not establish originality, operational advantage, or generality. The manuscript and response should continue to identify the object as a candidate distinction and should not present the pilot as resolving the novelty critique.
