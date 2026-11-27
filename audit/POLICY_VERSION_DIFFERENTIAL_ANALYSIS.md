# Paired policy-version replay on the frozen Docker traces

## Question and scope

This retrospective study checks whether realistic edits to the existing Docker gateway policy change decisions on recorded five-event windows, and whether the ordinary per-version explanations expose different event/rule cores. It does not implement an explanation of the difference itself. The study uses one fixed policy and 30 frozen local-lab workload streams; it is not an independent holdout, an operational prevalence estimate, or an analyst-utility study.

## Frozen operations and selection

Three edits were fixed in `experiments/revision_policy_evolution.py` before scanning the event streams:

1. Tighten `D_BRUTEFORCE` from at least four to at least three failures.
2. Relax `D_BRUTEFORCE` from at least four to at least five failures.
3. Remove `D_ADMIN`.

Every five-event suffix window in every stream was evaluated under both immutable policy versions. The scan did not filter by attack label. For each operation, the first differing-decision window in sorted workload-file and event order was selected as a representative pair. Core families for both versions were independently enumerated using `independent_table` and `all_minimal_cores` and compared with the ablation implementation.

## Results

| Policy edit | Windows with changed decision | Representative decision | Version 1 minimal event/rule core | Version 2 minimal event/rule core |
|---|---:|---|---|---|
| Threshold 4 → 3 | 604 | NoAlert → Violation | `{e:4, A_AUTH_FAIL_SINGLE}` | `{e:2, e:3, e:4, D_BRUTEFORCE}` |
| Threshold 4 → 5 | 693 | Violation → NoAlert | `{e:1, e:2, e:3, e:4, D_BRUTEFORCE}` | `{e:4, A_AUTH_FAIL_SINGLE}` |
| Remove `D_ADMIN` | 179 | Violation → Gap | `{e:4, D_ADMIN}` | empty set |

All three representative decision pairs differ as specified. All six version-specific minimal-core families agree with the independent exhaustive checker. Output and generator hashes match the manifest in `results/revision/policy_evolution_pairs_v1/`.

## Interpretation and limitation

The replay confirms that these policy edits can alter decisions on this corpus and that the corresponding ordinary explanation cores can change. It does not establish the likelihood or operational impact of such updates. The empty core for `Gap` after removing `D_ADMIN` illustrates a key limitation: an explanation of each version's decision is not an explanation of why the decision changed. In particular, the new-version explanation does not identify the removed rule. A differential explanation needs an explicit edit domain and a paired target that relates both version decisions; that object, its guarantees, and its evaluation remain open.

This result supports a narrowly scoped feasibility statement for version-bound replay. It does not yet support a scientific claim that TracePolicy explains policy evolution or improves policy debugging. The study is suitable as an audit result and as motivation for the next formal task; manuscript integration should wait for a defined differential object and a fair comparison.

## Phase decision

**PARTIAL / NO-GO for policy-version explanation.** Versioned replay and ordinary per-version explanation are demonstrated on three specified edits, with independent core-family checks. Differential explanations, independent evaluation, realistic operational validation, and utility evidence remain outstanding.
