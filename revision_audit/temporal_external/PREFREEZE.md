# Chronological external acquisition and prospective choices

2026-10-12. No chronological table rows or REAPr labels have been inspected at this point.

Candidate: hosted DARPA THEIA E3 chronological Parquet derivative, `alafage/darpa_tc_e3_theia`, immutable revision `690e8889c36429db1f62da22ec7ac06254d76e6a`. Source README and repository metadata are retained. Event table expected size535,829,401bytes, SHA256 `08c006812b25b56c0e1f1e3fbceac144027fcee43f1adc81cd92491497f570e1`. This is a hosted transformation, not raw CDM. Timestamp/identity preservation must be audited before claiming temporal applicability.

Freeze choices before test labels/outcomes:

- Stable chronological order by actual event timestamp plus original row identity as tie breaker. Rows with missing timestamps excluded and counted. Never fabricate timestamps.
- Chronological splits at60% and80% of observed wall-clock range, using unlabelled timestamp bounds only. Include all retained rows in each partition; train/validation/test ranges never overlap.
- P0: top6 training current-event selectors, frequency at least20; lower priority fallback deny. P1: same selectors, additionally require one of at most3 most common training predecessor actions for the same observed subject, minimum sequence support20. Selectors with no eligible predecessor remain denied. Guard length2; no test/validation tuning.
- Retain subject-local predecessor history across the chronological split boundary as deployment context, but learn rules only from training. State is updated independently of prediction; labels never enter monitor state.
- Derived REAPr labels are accessed only after policy/hash freeze, with matching keyed IDs/tuples independently checked. If identity linkage cannot be validated, report semantic replay and withhold detection metrics rather than relabel.
- P0/P1 detection metrics and changes both reported, including unfavorable tradeoffs. Validation is descriptive only, not a parameter search.
- Up to32 P1 alerts selected in earliest timestamp/original row order for exact explanation checks, without consulting labels. Also retain up to32 temporal-delta examples; interpret samples as cases, not population estimates.
- For each selected case, compare canonical reference/indexed/incremental decisions, verify sufficient inclusion-minimal sets and counterexample witnesses over all frozen rules and two subject-local events. Try genuine Anchors and formal attribution on a bounded exported fixture only if runtime/resources permit; do not fabricate additional-method executions.

Prior static MAGIC derivative and its labels were already inspected in earlier revision work. Thus THEIA engagement familiarity exists; this chronology was unavailable and unopened. Describe the distinction explicitly rather than calling the entire engagement previously unseen. Cross-sensor/method reproducibility is the claim, not new independent attack-generation provenance.

Before any test decisions or labels, add P2 as a diagnostic positive temporal trigger: same verified process `EVENT_EXECUTE` followed by `EVENT_CONNECT` in consecutive process-local events (length2). This security-motivated probe is fixed now; it is not selected using test prevalence. P2 keeps P0 current-event allows and adds priority100 deny for that sequence, for at most8 rules/10 units. If the vocabulary is absent or no test sequence fires, report that result and do not replace the sequence. Export up to32 earliest P2 sequence-triggered alerts separately from P1 anomaly alerts. This tests temporal causal cores without promising detection improvement.
