# Computers & Security AI/ML moratorium fit assessment

**Checked:** 2026-11-28  
**Gate:** G15 — NOT VERIFIED  
**Submission advice:** hold this venue-specific route until the handling/editorial office clarifies the scope of the moratorium for this manuscript.

## Current publisher policy

Elsevier's current Computers & Security journal page states that, since early 2024, the journal has a moratorium on submissions featuring AI or ML as significant components. It says that applying AI/ML techniques to system-security or privacy problems will not be considered. The public wording defines a broad boundary but does not give a test for whether a deterministic policy-explanation paper with post-hoc XAI baselines counts as a significant AI/ML contribution.

Official source, checked 2026-11-28: <https://shop.elsevier.com/journals/computers-and-security/0167-4048>

## Manuscript-to-policy mapping

| Manuscript evidence | Fit implication |
|---|---|
| Title: “Inclusion-Minimal Event–Rule Explanations for Intrusion Detection under Versioned Policies” (line 83). | The work is framed as intrusion detection and explanation, within the journal's security domain. The title does not itself decide the AI/ML question. |
| The central formal semantics and evaluator use deterministic, explicit, versioned security policies (Sections 5–8; implementation `src/trace_policy_engine.py` in the public repository, bundled as `code/src/trace_policy_engine.py`). No learned detector is the decision oracle. | This supports an interpretation as formal policy analysis rather than an AI/ML detection method. |
| Section 2.2 is explicitly titled “Explainability and post-hoc XAI in IDS”; it positions LIME and SHAP and says the study evaluates intrinsic, SHAP, and LIME explanations against one policy-decision oracle (lines 254–265). | XAI is a material research component, not incidental background. The tested explainers are AI/ML-associated methods applied to IDS decisions, which may fall within the stated moratorium. |
| Section 6 reports KernelSHAP, LIME, scikit-learn and native-versus-certified explanation comparisons; the Docker experiment reports matched output, cost, sufficiency and minimality (lines 672, 758–943). | This makes the AI/ML-related component experimentally substantive, even though the oracle itself is a symbolic policy engine. |
| The prior editor decision supplied by the authors (9 October 2026) stated that the manuscript fell within the journal's aims and scope and proceeded to substantive review. | This is case-specific evidence that the earlier version was treated as in scope. The letter did not discuss the moratorium or explicitly exempt the revised/new submission. |

## Assessment

The manuscript is neither plainly an ML-based detector nor plainly free of a substantial AI/ML component. Its core guarantee concerns deterministic policy decisions; however, post-hoc XAI methods are directly compared in the problem framing and experiments. The public moratorium text leaves that boundary open. The prior review is relevant evidence, but it does not settle current eligibility for a new submission.

Therefore, G15 remains **NOT VERIFIED**. It would be unsound to claim either an exemption or certain exclusion from the public wording alone. Rephrasing the title or removing words such as “XAI” would not resolve the underlying scientific role of SHAP/LIME in the study.

## Required clarification

Before treating Computers & Security as a viable venue, obtain a written editorial determination based on a short accurate description of the actual manuscript. A concise question is:

> The manuscript studies inclusion-minimal explanations for deterministic, explicit, versioned intrusion-detection policies. It does not use a learned detector as its decision oracle, but it includes substantive KernelSHAP and LIME comparisons as explainer baselines. Does this work fall within the journal's current moratorium on submissions featuring AI/ML as significant components?

No inquiry has been sent. The user-provided editor letter is evidence only for the earlier submission's scope treatment.
