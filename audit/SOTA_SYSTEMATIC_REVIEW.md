# SOTA review — current-source audit (in progress)

**Audit date:** 2026-11-26
**Scope of this increment:** full-text review of eight directly relevant primary works.
**Status:** preliminary; this is not a completed systematic review and does not establish novelty.

## Method and limits

The full papers linked below were opened and examined beyond their abstracts, including the sections describing the problem, formal objects or system pipeline, evaluation, and stated limitations. The comparison is intentionally epistemic: **not established in the examined source** is recorded as *unestablished*, not as proof that a capability is absent. The selected works cover (i) policy-decision explanations, (ii) abductive policy analysis that changes both facts and rules, (iii) recent provenance-based intrusion detection and attribution, (iv) formal feature attribution/MUS–MCS, and (v) counterfactual IDS explanations. Further coverage remains necessary for additional formal XAI variants, policy debugging, versioned policy explanation, and distributed monitoring.

## Primary full-text studies

### Marfia (2014), policy explanations by abduction and induction

Marfia presents two approaches over OWL-DL/SWRL and the PoSecCo policy language: an exact abductive/OWL-justification procedure that identifies policies involved in a permission or denial, and an inductive association-rule procedure that identifies attributes associated with privileges. The paper explicitly targets explanations of access decisions, including denials. This is a direct prior-work collision with any broad claim that TracePolicy is the first method to explain policy decisions or to use abduction for policy explanation.

The paper’s explanation object is an ontology justification or an attribute/fact pattern. The reviewed sections do not establish TracePolicy’s trace-event intervention domain, universally sufficient event–rule cores under a fixed decision semantics, inclusion-minimality over that joint intervention universe, or version-differential explanation. These distinctions are candidates for positioning, not yet a novelty proof. The paper itself warns that exact justifications may become too numerous or difficult for end users to read.

Primary source: [full proceedings paper, DOI 10.5220/0005116004570462](https://doi.org/10.5220/0005116004570462), 11th International Conference on Security and Cryptography (SECRYPT 2014), pp. 457–462.

### Gupta, Stoller, and Xu (2014), abductive administrative-policy analysis

The TDSC paper defines ACAR, an administrative framework controlling addition and removal of both facts and rules, and computes minimal sets of initial facts that make an atom reachable through sequences of authorized administrative changes. Its full text distinguishes prior frameworks that changed facts only and explains the translation of rule changes into fact changes under ACAR’s design. It is therefore a close collision for generic novelty claims about joint fact/rule reasoning, abduction, or minimality.

The target question is administrative reachability under possible future policy changes and partially unknown initial facts. It is not, as specified in the examined text, an explanation of one observed IDS decision over a fixed event trace and a policy snapshot. The unit of abduction, temporal semantics, decision-preservation condition, and operational output differ. This difference may support a narrower contribution, but only a full formal comparison against TracePolicy’s actual definitions and other neighboring work can establish that.

Primary source: [full TDSC paper, DOI 10.1109/TDSC.2013.42](https://doi.org/10.1109/TDSC.2013.42), 11(5), 412–424. An earlier version appeared in ICISS 2011; the journal version is the appropriate primary comparison for the mature algorithm and claims.

### Jiang et al. (2025), ORTHRUS

ORTHRUS uses temporal graph learning to detect malicious hosts in provenance graphs, then performs dependency analysis to reconstruct attack paths and improve quality of attribution. The full paper frames quality of attribution around analyst investigation effort and compares its output with five IDSs. Its explanation-like output is a concise attack-summary/provenance graph, not merely a feature attribution score.

This is a direct collision with broad claims that prior IDS explanations are only feature rankings or that attack attribution from provenance is unaddressed. The examined paper does not establish a universally sufficient, inclusion-minimal set of event and policy-rule interventions that preserves a particular rule-based decision. Conversely, TracePolicy’s smaller certified core does not establish equivalent forensic attribution quality, attack-path completeness, or lower analyst effort. These are distinct objectives and should be compared as such.

Primary source: [full USENIX Security 2025 paper](https://www.usenix.org/system/files/usenixsecurity25-jiang-baoxiang.pdf), pp. 7173–7192; [official conference record and artifact links](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang).

### Wang et al. (2025), CAPTAIN

CAPTAIN is a rule-based provenance IDS with a learning module that adjusts entity-tag initialization, propagation, and alarm thresholds from false alarms. The paper describes system events and rule-triggered alarms, and evaluates detection behavior, latency, overhead, and interpretability. This directly undercuts any broad contrast between explainable rule-based intrusion detection and learning-based methods, and any characterization of rule-based PIDS as necessarily static or manually configured.

Its learned object is a detector configuration; the paper does not, in the examined sections, define a certified minimal intervention explanation over an observed trace and frozen policy version. TracePolicy’s decision-explanation guarantees, if verified, concern a different output and evaluation target. The distinction must be stated without implying CAPTAIN lacks explanations or that fixed-rule analysis is inherently superior.

Primary source: [full NDSS 2025 paper](https://www.ndss-symposium.org/wp-content/uploads/2025-822-paper.pdf); [official NDSS record](https://www.ndss-symposium.org/ndss-paper/incorporating-gradients-to-rules-towards-lightweight-adaptive-provenance-based-intrusion-detection/).

### Yu et al. (2024), formal feature attribution

The SAT 2024 paper defines formal feature attribution (FFA) as the fraction of abductive explanations containing a feature, relates abductive explanations to MUSes and contrastive explanations to MCSes, proves a #P-hardness result for exact counting, and proposes an anytime approximation using enumeration and switching. TracePolicy already includes an FFA-style analysis, but its implementation consumes the complete family of small-domain cores from its own exact enumeration; this is a definition-level adaptation, not the authors' anytime method. Cost attribution must include full core enumeration, and FFA ranks membership frequency rather than certifying a uniquely privileged cause.

Primary source: [full SAT 2024 paper, DOI 10.4230/LIPIcs.SAT.2024.30](https://doi.org/10.4230/LIPIcs.SAT.2024.30), pp. 30:1–30:23; [official Dagstuhl record and artifact metadata](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.SAT.2024.30).

### Burkart, Franz, and Huber (2021), IDS explanation framework

This full-text conference chapter proposes explanations for IDS alerts using counterfactual instances and locally faithful decision boundaries to support operator review. It establishes that alert-level explanation and operator-facing reports predate TracePolicy. Its stated problem is model-oriented local explanation; the examined text does not define an intervention over versioned policy-rule units jointly with observed event positions, nor a universal sufficiency/minimality certificate for such a domain. This is a scope distinction, not a comparative quality result.

Primary source: [full open-access chapter, DOI 10.1007/978-3-662-62746-4_9](https://doi.org/10.1007/978-3-662-62746-4_9), pp. 83–91.

### Ribeiro, Singh, and Guestrin (2018), Anchors

Anchors are local if-then rules intended to have high precision under a perturbation distribution: when an anchor holds, the black-box prediction is expected to remain the same with high probability. The paper gives a sampling-based algorithm with probability guarantees and evaluates the approach across domains, including a user study. Anchors therefore already supply local sufficient-condition explanations and empirical human-utility evidence. Their guarantee is distributional and local; it is not the universal deterministic preservation property over TracePolicy's declared finite event/rule intervention cube. The paper also discusses coverage, overly specific anchors, and perturbation-distribution realism. A comparison must separate native Anchors outputs from any exact post-certification/minimization, and must not transfer the source paper's user-study result to TracePolicy.

Primary source: [full AAAI-18 paper, DOI 10.1609/aaai.v32i1.11491](https://doi.org/10.1609/aaai.v32i1.11491), pp. 1527–1535; [official AAAI PDF](https://cdn.aaai.org/ojs/11491/11491-13-15019-1-2-20201228.pdf).

### Janicke, Cau, Siewe, and Zedan (2012), dynamic access-control policies

This work gives a compositional formal framework for specifying and verifying temporal access-control policies, including history-based constraints and policies that evolve dynamically. It establishes that temporal policy semantics and policy evolution are prior formal-policy topics. It does not, in the examined paper, provide an explanation object that identifies a minimal jointly sufficient subset of an observed IDS trace and a frozen policy version. This is a boundary in the target object, not evidence that versioning itself is novel. A detailed comparison of its policy-evolution semantics with TracePolicy's versioned decision binding remains necessary before the versioning claim can be evaluated.

Primary source: [full Computer Journal paper, DOI 10.1093/comjnl/bxs102](https://doi.org/10.1093/comjnl/bxs102); author-hosted full text at [De Montfort University](https://www.tech.dmu.ac.uk/~fsiewe/papers/helge_siewe_2012.pdf).

## Collision findings

1. **Generic policy explanations are established prior art.** Marfia (2014) already provides abductive explanations for permission and denial decisions.
2. **Joint handling of facts and rules is established prior art for a different problem.** Gupta et al. (2014) compute abductive reachability conditions under administrative changes to facts and rules. A “facts plus rules” combination alone cannot be the novelty claim.
3. **IDS attribution and causal-path output are established prior art.** ORTHRUS provides path reconstruction and analyst-oriented attribution; the manuscript must define its decision-level certification separately and avoid claiming forensic superiority without evidence.
4. **Rule-based PIDS can be adaptive and learning-enabled.** CAPTAIN makes a static-versus-adaptive dichotomy untenable.
5. **Potentially differentiating conjunction:** explanations over a concrete observed event trace and a frozen/versioned decision policy, where both event units and policy-rule units are admissible interventions, with a checkable universal-sufficiency certificate and per-unit necessity witnesses. This is only a *candidate distinction*: its exact semantics, novelty against all neighboring work, nontrivial empirical value, and practical relevance remain unverified.
6. **Formal feature attribution is not an equivalent baseline by default.** It averages membership across all abductive cores; TracePolicy's FFA-style computation inherits the cost of complete core enumeration and should be compared on that precise basis.
7. **IDS counterfactual frameworks already target alert explanations.** The paper must distinguish its retained-evidence decision certificate from model-local boundary/counterfactual explanations, without claiming these are invalid or less useful.

## Required next comparisons

- Inspect the actual manuscript definitions and theorems line by line against these papers; determine whether TracePolicy’s rule units are policy rules, operational detector rules, or both.
- Audit the complete proof of every claimed certificate and distinguish preservation of the observed decision from causal attribution of the attack.
- Examine full text for Anchors, SHAP/LIME, formal feature attribution and MUS/MCS; compare native output, intervention domain, sufficiency, minimality notion, and certification cost.
- Complete source-level comparison for Anchors, SHAP/LIME, and additional counterfactual IDS explanation frameworks; the two formal texts above do not close this category.
- Review policy debugging, provenance-based explanation, temporal/versioned policies, and distributed monitoring sources, including the sources already collected in `revision_audit/literature_evidence.md`.
- Search for work post-dating the manuscript’s current literature cutoff and confirm publication/version metadata from publisher or proceedings records.
- Establish whether the contribution is substantial enough for the current Computers & Security submission policy; journal-fit remains an independent blocking issue in `SCIENTIFIC_GAP_REGISTER.csv`.

## Phase decision

**NO-GO for closing Phase 2.** Six full texts are reviewed and they materially narrow the defensible novelty framing, but the prescribed topic coverage and full-text collision matrix are incomplete. No claim of originality or journal suitability is made by this increment.
