# Four-way joint explanation ablation

**Run:** 2026-11-26, revision branch worktree.
**Script:** `experiments/revision_union_ablation.py`.
**Output:** `results/revision/joint_union_ablation_v1/`.
**Interpretation:** retrospective workload characterization plus a constructed semantic falsification witness.

## Question

Does combining event-only and rule-only minimal explanations produce a universally sufficient or inclusion-minimal explanation in the joint event–rule intervention domain? Does joint enumeration yield outputs that the complete families of separated cores cannot supply?

## Method

For each case, the experiment obtains *all* inclusion-minimal event-only cores, all rule-only cores, and all exact joint cores. It then tests every Cartesian-product union in the complete joint intervention domain. Sufficiency and per-unit deletion minimality use complete intervention tables constructed by the separate `revision_explanation_benchmark.independent_table` routine, rather than trusting the union generator's own returned certificates. The constructed witness's core families are additionally compared with this independent full-table enumeration.

The Docker case selection and existing nine fixtures are retrospective. The separate semantic witness is adversarial and constructed to test the universal composability claim; it is not a prevalence estimate or independent real-world validation.

## Results

| Group | Cases | Union candidates | Sufficient unions | Cases with at least one exact joint-minimal union | Cases where every union is sufficient |
|---|---:|---:|---:|---:|---:|
| Selected Docker alerts | 120 | 168 | 168 | 120 | 120 |
| Existing controlled fixtures | 9 | 11 | 11 | 9 | 9 |
| Constructed semantic witness | 1 | 4 | 2 | 1 | 0 |

No sufficient-but-nonminimal union was observed in these groups. In the witness, the two crossed event/rule pairings fail, with saved assignments producing `Gap` while the factual target is `Violation`. The two matched pairings are jointly sufficient and minimal.

## Reproduction and integrity

Run from the repository root with the revision Python environment:

```powershell
& ..\environment\Scripts\python.exe experiments\revision_union_ablation.py
& ..\environment\Scripts\python.exe scripts\verify_joint_union_ablation.py
```

The output directory contains per-case and per-union JSON, a summary, and a protocol manifest with input, script, and output hashes. The original three-mode outputs under `joint_ablation_v1/` were preserved.

## Limitations and decision

The selected Docker alerts and nine fixtures provide descriptive finite-domain evidence only. The constructed witness proves a semantic possibility under the implementation, not its frequency in deployment. No independent holdout or analyst-utility experiment is included. The result therefore supports an open research question about the value of joint search, rather than a claim of practical superiority.

**Gate status: NOT VERIFIED / NO-GO.** A full characterization and a prespecified independent evaluation remain necessary before this ablation can support a strong novelty or generalization claim.
