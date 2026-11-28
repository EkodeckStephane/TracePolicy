# Generic AXp baseline on the paired policy pilot

**Date:** 2026-11-28  
**Decision:** baseline algorithm check PASS on the three frozen pilot cases; originality and external validity remain NOT VERIFIED.

## Question and method

The paired event/edit pilot can be viewed as a Boolean function over factual retention literals. For each admissible assignment whose ordered old/new alert pair differs from the factual target, the coordinates set to zero form a conflict: a sufficient explanation must retain at least one coordinate that blocks that completion. The generic AXp family is therefore the family of inclusion-minimal hitting sets of these conflict sets.

`experiments/revision_generic_axp_baseline.py` constructs these conflict sets from each complete truth table and enumerates their minimal hitting sets. This algorithmic route differs from the pilot's direct powerset enumeration of sufficient retained sets. It compares complete families rather than one selected explanation.

## Results

| Fixed policy edit | Assignments | Non-target conflicts | Generic AXp family | Match |
|---|---:|---:|---|---|
| Tighten brute-force threshold | 64 | 60 | `{e:2, e:3, e:4, d:D_BRUTEFORCE.count_threshold}` | Yes |
| Relax brute-force threshold | 64 | 62 | `{e:1, e:2, e:3, e:4, d:D_BRUTEFORCE.count_threshold}` | Yes |
| Remove admin deny rule | 64 | 48 | `{e:4, d:D_ADMIN.presence}` | Yes |

The complete family matches the stored paired pilot in all three cases. Results and a hash manifest are in `results/revision/generic_axp_baseline_v1/`.

## Limits

The baseline shares the frozen reference evaluator, event/edit intervention semantics, and representative-window selection with the pilot. It independently checks the enumeration principle, but it is not an independent semantics implementation or oracle. It therefore validates the constrained-AXp correspondence for these finite tables, not the correctness of the policy evaluator. It supplies no comparison with native Margrave, no independent policy family, and no operational utility evidence.

The outcome strengthens the prior-art collision: the paired pilot's complete minimal explanations are recovered by generic AXp machinery without a TracePolicy-specific explanation algorithm. A remaining contribution, if any, must lie in a useful, rigorously specified event/edit intervention semantics or in measured diagnostic utility. This result does not establish either.

## Reproduction

From the repository root:

```powershell
python experiments\revision_generic_axp_baseline.py
```

The script writes only to the new `generic_axp_baseline_v1` output directory and leaves the earlier pilot archive unchanged.
