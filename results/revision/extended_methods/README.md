# Same-instance expanded explanation comparison

Executed retrospectively on the exact120 selected true-positive Docker alerts from all30 workloads, using `local_lab_proofmatched/run_manifest.json`. Source IDs, sixty input hashes, policy hash, ordering and explanatory unit counts were checked before execution. No case was resampled and no policy was tuned.

- Genuine Alibi AnchorTabular: **360/360 completed**, three seeds11,23,47 per case; all native selected sets sufficient and inclusion-minimal under independent full-domain validation. Native precision estimates are1.0 in this campaign, not a universal guarantee. Native selected sets were never repaired.
- Exact FFA definition adaptation: **120/120 completed**, all certified selected prefixes sufficient and inclusion-minimal. It computes the complete minimal-core family and membership frequencies; it does not implement or benchmark the SAT2024 authors' anytime solver.
- All120 independently reconstructed truth tables and core families agree between the two NumPy environments. There are104 one-core instances and16 four-core authentication instances.
- Authentication mean Jaccard against the deterministic intrinsic core is0.822222 for both expanded methods despite complete validity. The three instantaneous scenarios have agreement1.0.

`anchors.json/csv` and `ffa.json/csv` retain every measured output, selected units, seed, phases and actual certificate witnesses. `case_catalog.json` contains full selected traces. `oracle_tables/case_*.npz` store complete class tables and all minimal core masks without pickle: integer mask `k` retains unit `i` iff `k & (1 << i)` is nonzero. `comparative_summary.json` summarizes evidence without treating three Anchor seeds as independent workloads.

The FFA enumeration uses canonical evaluation with state replay cached once per event mask, followed by an exact bad-superset dynamic program costing O(m·2^m), not a3^m subset loop. Its total includes table construction, core enumeration, frequencies, prefix selection and fixed-set proof. This backend optimization and the richer complete-core output prevent attributing a wall-time difference solely to the FFA definition.

Anchors uses the complete uniformly weighted binary reference population and threshold0.95. Its predictor starts with an **empty per-explanation memoization cache** and evaluates each new mask canonically; it never reads the independently precomputed audit table. All cache construction costs are included in native time. Request counts and unique canonical evaluations are recorded separately. A separate exhaustive audit table validates native outputs outside native timing; fixed-set proof construction is included in total delivered-output cost. The first outer native call includes lazy Alibi import and reference-population construction:3.833s outer time versus0.638s for the helper's narrower fitted-explainer interval. Its cold-import flag is retained. No measurement was adjusted to erase this overhead.

The120s deadline is checked on independent table and native prediction callbacks, not enforced by a hard process kill. No timeout or failure occurred. Proof construction is bounded by the observed9–13-unit domains (118instances at13units, one at11 and one at9). Runtime environments are separate; this campaign supports feasibility and output validity, not comparative timing superiority or analyst utility.

Reproduce with the configured Python environments:

```powershell
& revision_COSE_2026/environment_anchors/Scripts/python.exe revision_COSE_2026/code/experiments/revision_extended_methods.py --method anchors
& revision_COSE_2026/environment/Scripts/python.exe revision_COSE_2026/code/experiments/revision_extended_methods.py --method ffa
& revision_COSE_2026/environment/Scripts/python.exe revision_COSE_2026/code/experiments/revision_extended_summary.py
```

`tests/test_extended_methods.py` passes13 tests, comparing DP against independent exhaustive extraction for all nine controlled cases, arbitrary nonmonotone truth functions, and a full13-unit threshold fixture with four alternative cores.
