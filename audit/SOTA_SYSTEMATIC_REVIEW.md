# SOTA review — current-source audit (in progress)

**Audit date:** 2026-11-26
**Scope of this increment:** full-text review of twelve directly relevant primary works.
**Status:** preliminary; this is not a completed systematic review and does not establish novelty.

## Method and limits

The full papers linked below were opened and examined beyond their abstracts, including the sections describing the problem, formal objects or system pipeline, evaluation, and stated limitations. The comparison is intentionally epistemic: **not established in the examined source** is recorded as *unestablished*, not as proof that a capability is absent. The selected works cover policy explanation and abduction, formal feature attribution, static policy diagnosis, dynamic access-control policies, IDS alert explanation, provenance-based attack reconstruction, and distributed monitoring. Further coverage remains necessary for additional formal XAI and policy explanation variants and work specifically explaining decisions across policy versions.

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

### Yuan et al. (2006), FIREMAN

FIREMAN models firewall configurations as finite-state programs and applies BDD-based static analysis to detect policy violations and rule inconsistencies/inefficiencies across individual and distributed firewalls and network paths. The paper reports confirmed production misconfigurations. It is prior art for formal rule analysis and distributed policy debugging, while its object is static packet-space/path compliance rather than an explanation of a particular observed IDS trace decision through joint event/rule retention.

Primary source: [full IEEE S&P 2006 paper, DOI 10.1109/SP.2006.16](https://doi.org/10.1109/SP.2006.16); author-hosted full text at [UC Davis](https://www.cs.princeton.edu/courses/archive/fall10/cos561/papers/FireMan06.pdf).

### Hu, Ahn, and Kulkarni (2012), FAME firewall anomaly management

FAME partitions packet space into disjoint regions associated with sets of firewall rules, thereby identifying multi-rule overlap, conflict and redundancy; it also supplies visual diagnosis and resolution strategies. The source directly collides with any broad claim that identifying interacting or redundant policy rules is new. Its diagnosis concerns static packet-space anomalies and rule resolution, not event evidence and preservation of one version-bound intrusion decision.

Primary source: [full IEEE TDSC paper, DOI 10.1109/TDSC.2012.20](https://doi.org/10.1109/TDSC.2012.20), 9(3), 318–331; [author-hosted full text](https://sefcom.asu.edu/publications/detecting-resolving-firewall-tdsc2012.pdf).

### Cheng et al. (2024), KAIROS

KAIROS is a whole-system provenance PIDS whose temporal graph model scores anomalous system events and reconstructs compact attack-summary graphs. The authors explicitly treat attack reconstruction and human investigation as central design/evaluation dimensions and discuss dataset and metric limitations in PIDS evaluation. This is a direct collision with broad IDS explainability or attack-investigation claims. KAIROS explains/investigates activity through graph summaries; TracePolicy's possible distinction is a decision-preservation certificate over explicit event and policy-rule interventions. The outputs, assumptions and utility measures differ, so no comparative superiority follows.

Primary source: [full IEEE S&P 2024 paper, DOI 10.1109/SP54263.2024.00005](https://doi.org/10.1109/SP54263.2024.00005), pp. 3533–3551; [authors' full text](https://tfjmp.org/publications/2024-sp.pdf).

### Wu et al. (2023), Paradise

Paradise presents a real-time, generalized, distributed provenance-based IDS. It represents process behavior in feature vectors and distributes independent detection work, addressing heterogeneous provenance collection and distributed monitoring. This establishes distributed PIDS as substantial prior art. It does not define a jointly sufficient minimal event/rule explanation for a versioned declarative policy decision. TracePolicy's cross-instance integration must therefore be described as a bounded systems demonstration, not as a new distributed IDS architecture or evidence of distributed attack-detection performance.

Primary source: [full IEEE TDSC paper, DOI 10.1109/TDSC.2022.3160879](https://doi.org/10.1109/TDSC.2022.3160879), 20(2), 1624–1640; [author-hosted full text](https://darrelllong.github.io/pdfs/wu-paradise.pdf).

### Brucker and Petritsch (2011), versioned policy analysis and replay

This framework stores policy versions and access-control logs together, including the active policy version, decision, obligations, and context attributes. It supports replaying a recorded request against another policy version and comparing the resulting decisions; the paper illustrates precisely this kind of cross-version re-evaluation. Policy version comparison and replay are therefore established prior art. The reviewed work does not define a subset-minimal joint intervention over the recorded trace and policy rules, nor a differential explanation certificate for why a decision changed. Those distinctions are candidate differences requiring direct formal and experimental comparison, rather than grounds for a broad novelty claim about version-aware explanation.

Primary source: [full IEEE POLICY 2011 paper, DOI 10.1109/POLICY.2011.47](https://doi.org/10.1109/POLICY.2011.47), pp. 105–112; [author-hosted publication record](https://brucker.ch/publications/by-topic/) and [full text](https://logicalhacking.com/publications/brucker.ea-framework-2011/brucker.ea-framework-2011.pdf). The author-copy PDF's title block reverses the author order; the proceedings contents and Brucker's publication record identify Achim D. Brucker first and Helmut Petritsch second, which is used here.

### Ignatiev et al. (2020), abductive and contrastive explanation duality

This full-text paper establishes a formal relationship between local abductive explanations (“why this prediction?”) and contrastive explanations (“what change would alter it?”): each family is the set of minimal hitting sets of the other, using the MUS/MCS duality. Consequently, minimal sufficient explanations and minimal change explanations, and their enumeration, are mature formal-XAI topics. TracePolicy must locate its contribution in the particular semantics of retained trace events and policy rules, its version binding, and any independently verified certificates; inclusion-minimality and MUS/MCS-style reasoning alone are not novel contributions.

Primary source: [full Springer chapter, AIxIA 2020 proceedings (published 2021), DOI 10.1007/978-3-030-77091-4_21](https://doi.org/10.1007/978-3-030-77091-4_21), pp. 335–355; [author-hosted full text](https://alexeyignatiev.github.io/assets/pdf/inams-aiia20-preprint.pdf).

## Collision findings

1. **Generic policy explanations are established prior art.** Marfia (2014) already provides abductive explanations for permission and denial decisions.
2. **Joint handling of facts and rules is established prior art for a different problem.** Gupta et al. (2014) compute abductive reachability conditions under administrative changes to facts and rules. A “facts plus rules” combination alone cannot be the novelty claim.
3. **IDS attribution and causal-path output are established prior art.** ORTHRUS provides path reconstruction and analyst-oriented attribution; the manuscript must define its decision-level certification separately and avoid claiming forensic superiority without evidence.
4. **Rule-based PIDS can be adaptive and learning-enabled.** CAPTAIN makes a static-versus-adaptive dichotomy untenable.
5. **Potentially differentiating conjunction:** explanations over a concrete observed event trace and a frozen/versioned decision policy, where both event units and policy-rule units are admissible interventions, with a checkable universal-sufficiency certificate and per-unit necessity witnesses. This is only a *candidate distinction*: its exact semantics, novelty against all neighboring work, nontrivial empirical value, and practical relevance remain unverified.
6. **Formal feature attribution is not an equivalent baseline by default.** It averages membership across all abductive cores; TracePolicy's FFA-style computation inherits the cost of complete core enumeration and should be compared on that precise basis.
7. **IDS counterfactual frameworks already target alert explanations.** The paper must distinguish its retained-evidence decision certificate from model-local boundary/counterfactual explanations, without claiming these are invalid or less useful.
8. **Policy debugging is established prior art.** FIREMAN and FAME analyze misconfiguration, conflicts, shadowing/redundancy and rule interactions, including distributed firewall configurations. TracePolicy's bounded diagnosis cannot be claimed as the first formal policy diagnosis; its target is a trace-conditioned alert and declared versioned intervention domain.
9. **Attack reconstruction and distributed PIDS are established capabilities.** KAIROS generates attack-summary graphs for investigation, and Paradise provides real-time distributed provenance-based detection. TracePolicy must delimit its explanation contract and one cross-instance systems demonstration from these broader detection/reconstruction capabilities.
10. **Policy-version replay and decision comparison predate TracePolicy.** Brucker and Petritsch bind log records to active policy versions and replay requests against alternative versions. The candidate distinction is a trace-and-rule intervention core or a certified explanation of the decision difference; its semantics and value still need direct comparison.
11. **Formal abductive/contrastive duality is established.** Ignatiev et al. connect AXps and CXps through MUS/MCS and minimal hitting-set duality. TracePolicy's novelty cannot rest on minimal sufficient sets, subset-minimality, or this duality alone.

## Required next comparisons

- Inspect the actual manuscript definitions and theorems line by line against these papers; determine whether TracePolicy’s rule units are policy rules, operational detector rules, or both.
- Audit the complete proof of every claimed certificate and distinguish preservation of the observed decision from causal attribution of the attack.
- Examine additional SHAP/LIME and formal-XAI/MUS-MCS full texts; compare native output, intervention domain, sufficiency, minimality notion, and certification cost. Anchors and one counterfactual IDS framework have been reviewed.
- Compare TracePolicy's paired-version example and formal change explanation directly with Brucker and Petritsch (2011), including recorded context, policy version, replay, and decision-difference outputs.
- Review further policy debugging, provenance-based explanation, temporal/versioned policies, and distributed monitoring sources, including sources already collected in `revision_audit/literature_evidence.md`; the four new full texts narrow but do not exhaust these topics.
- Search for work post-dating the manuscript’s current literature cutoff and confirm publication/version metadata from publisher or proceedings records.
- Establish whether the contribution is substantial enough for the current Computers & Security submission policy; journal-fit remains an independent blocking issue in `SCIENTIFIC_GAP_REGISTER.csv`.

## Phase decision

**NO-GO for closing Phase 2.** Twelve full texts are reviewed and they materially narrow the defensible novelty framing, but the prescribed topic coverage and full-text collision matrix are incomplete. No claim of originality or journal suitability is made by this increment.
