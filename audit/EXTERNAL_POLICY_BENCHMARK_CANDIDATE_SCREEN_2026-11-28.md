# External versioned detection-policy benchmark candidate screen

**Screen date:** 2026-11-28  
**Candidate:** SigmaHQ rule repository and its regression samples  
**Disposition:** promising source for a prespecified policy-evolution study; not yet an admissible independent confirmatory benchmark.

## Frozen source identity

- Repository: <https://github.com/SigmaHQ/sigma>
- Branch: `master`
- Screened commit: `ddf1d4f87fd283513ac1dbf7e178c8a4064047df` (2026-11-28)
- Rule repository license notice: Sigma specification is public domain; rules are subject to Detection Rule License (DRL) 1.1. Do not copy rule text or sample telemetry into TracePolicy until its reuse and redistribution terms are reviewed.
- Regression-data index at the frozen commit: <https://github.com/SigmaHQ/sigma/tree/ddf1d4f87fd283513ac1dbf7e178c8a4064047df/regression_data>

## Fit to the research question

The official Sigma specification defines event detection rules and a separate correlation-rule format. The latter includes event-count, value-count, temporal and ordered-temporal correlation types with group-by fields and time spans. The Sigma repository also contains regression cases backed by EVTX and JSON/NDJSON samples, and its documented CI checks expected match counts. The public Git history provides versioned rule changes.

These properties make Sigma more promising for realistic detection-rule evolution than the hand-authored Docker policy alone. It offers identifiable rule versions, rule IDs, explicit temporal correlation constructs, and event samples suitable for replay.

## Blocking limitations before admission

1. The regression samples are attached to their rules and selected to verify those rules. Their positive-match expectation creates rule/test coupling and cannot be treated as an untouched external test set.
2. The rule repository's DRL 1.1 applies to rule content. The benchmark must retain source commit and rule identifiers and hashes while resolving whether derived policy encodings, test excerpts, and redistributed samples are permitted.
3. Sigma is a format, not a single reference execution engine. Conversion pipelines and backend semantics affect matching. A benchmark must pin the specification version, converter, pipeline, backend/query engine, and time-correlation semantics.
4. TracePolicy's current Python policy semantics are not a Sigma interpreter. An adapter over a restricted subset would need a formal mapping and differential tests against the pinned Sigma engine; otherwise the benchmark measures a new model, not existing Sigma semantics.
5. Correlation policies operate over event streams and time windows; trace segmentation, window anchoring, ordering, grouping and missing events must be fixed before evaluating policy edits.
6. Historical revisions that introduce or update regression cases cannot be paired naively with those same cases. The selection procedure must require event samples committed before the policy change under study and replay each unchanged sample under both versions.

## Prospective selection protocol (not yet executed)

1. Pin a full Sigma repository commit and specification/converter versions; record repository license notices.
2. Build a metadata-only history index of stable/test detection and correlation rules. For each rule ID, enumerate commits changing detection logic or correlation structure; exclude title-only, metadata-only, formatting-only and unsupported backend constructs using criteria fixed before replay.
3. Require at least one unchanged regression sample committed before the rule-change commit. Hash it at its original commit. Do not select cases by whether the old/new decisions differ.
4. Use a pinned native or reference Sigma-compatible engine to evaluate the same pre-existing stream under both policy versions. Preserve all input events; separately define event-retention and rule-edit interventions. Record window boundaries and grouping keys.
5. Compare full event-only, rule-edit-only, naive union and joint event/edit explanations against a shared oracle. Include an independent generic AXp enumerator and report native outputs separately from the certified/minimized outputs.
6. Treat the paired result as a retrospective policy-history benchmark. Keep all tests rule-linked in a separate descriptive stratum. A confirmatory generalization claim requires held-out rule families or telemetry not used to create or revise the tested rules.
7. Publish only permitted identifiers, hashes, derived metrics and scripts; obtain and document permission/license interpretations before packaging source rule text or raw event files.

## Admission decision

**Candidate screen: PASS. Benchmark admission: NOT VERIFIED.** Sigma history and regression assets appear to support a concrete follow-up protocol, but the source's rule/test coupling, rule license, engine semantics and adapter validity remain unresolved. No experiment, dataset extraction, or generalization result is claimed in this screen.

**Gate effect:** G9 remains NOT VERIFIED; G8 remains OPEN until licensing and clean reproduction are addressed; G5 remains NOT VERIFIED. The current study retains its NO-GO status.

## Primary sources

- Sigma rule repository license notice: <https://github.com/SigmaHQ/sigma/blob/ddf1d4f87fd283513ac1dbf7e178c8a4064047df/LICENSE>
- Sigma regression test documentation: <https://github.com/SigmaHQ/sigma/blob/ddf1d4f87fd283513ac1dbf7e178c8a4064047df/regression_data/README.md>
- Sigma rule specification 2.1.0: <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md>
- Sigma correlation specification 2.1.0: <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md>
- Detection Rule License 1.1: <https://github.com/SigmaHQ/Detection-Rule-License>
