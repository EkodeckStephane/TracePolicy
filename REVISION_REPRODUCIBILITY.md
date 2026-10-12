# Reproducing the dedicated revision

Run from the repository root with Python3.11. Create two separate environments from `requirements-revision.txt` and `requirements-anchors-revision.txt`; SHAP and Alibi require different NumPy major versions. The original README/drivers and old results describe the historical release. `run_all.sh` is not the revision runner.

Main environment:

```bash
python -m pytest tests -q
python experiments/revision_running_example.py
python experiments/revision_explanation_benchmark.py
python experiments/run_rq2_local_lab_explanations.py --selection stratified --selection-seed 20261011 --proof-matched --quiet
python experiments/revision_scaling.py --proof-matched
python experiments/revision_methods.py --ffa --out revision_audit/ffa_benchmark.json
python experiments/revision_methods.py --out revision_audit/two_source_replay.json
python experiments/revision_extended_methods.py --method ffa
python experiments/revision_extended_summary.py
python experiments/revision_distributed_lab.py --help
python scripts/verify_frozen_protocol_v2.py
```

Alibi environment:

```bash
python experiments/revision_methods.py --anchors --out revision_audit/anchors_benchmark.json
python experiments/revision_extended_methods.py --method anchors
```

The default extended method driver uses the exact120 saved Docker strata and checks portable input copies against recorded hashes. Complete proof costs for SHAP/LIME are in `local_lab_proofmatched/`; extended methods have different cache backends and environments, so no timing superiority follows from those durations. Preserve supplied results before reruns: some drivers intentionally regenerate outputs.

Distributed live execution is implemented by portable `serve`, `collect`, `prepare` roles. The `local` role exercises two live collector processes and a coordinator on one host; it does not constitute separate-host deployment. Review its CLI and protocol before selecting output paths. Dedicated cross-environment results, when present, state their exact topology, fault profiles and incomplete outcomes.

External static MAGIC verification requires the third-party archive, not bundled here. Acquire `data/theia.zip` from the [MAGIC repository](https://github.com/FDUDSDE/MAGIC), verify SHA256 `926b4e30a39b1680fe512ef015bfe03ab85760e12dc7d8ae88da40a346bd6864`, place it at `revision_audit/magic_theia_graphs.zip`, then run:

```bash
python experiments/revision_methods.py --external-static --out revision_audit/external_static_result.json
python experiments/revision_methods.py --external-static --out revision_audit/external_static_recheck.json
```

The static derivative loses chronology and inherits upstream label-assisted training filtering. The actual timestamp-preserving chronological campaign is documented in `revision_audit/temporal_external/README.md`, including pinned download URLs, source SHA256, actor direction, process-local history, labels and unfavorable detection results. Acquire the four Parquet files independently into `data/theia_chronological`; they and the working DuckDB database are excluded from Git. Allow several GB of scratch space. From the repository root:

```bash
python -m pip install -r requirements-temporal-revision.txt
python experiments/revision_temporal_external.py prepare --data-dir data/theia_chronological --output results/tmp/theia_chronological
python experiments/revision_temporal_external.py evaluate --data-dir data/theia_chronological --output results/tmp/theia_chronological
python experiments/revision_temporal_external.py labels --data-dir data/theia_chronological --output results/tmp/theia_chronological
python experiments/revision_temporal_external.py verify --data-dir data/theia_chronological --output results/tmp/theia_chronological
```

For prospective repetition, acquire/open labels only after `prepare` freezes the policies. To reproduce the saved explanation comparison without downloading 44 million events, use the supplied frozen catalogs (the commands below write new results):

```bash
python experiments/revision_catalog_methods.py --case-catalog revision_audit/temporal_external/results/p1_earliest_alerts_catalog.json --output results/tmp/theia_methods/earliest_alerts --methods tracepolicy,kernelshap,lime,ffa
python experiments/revision_catalog_methods.py --case-catalog revision_audit/temporal_external/results/p1_temporal_delta_catalog.json --output results/tmp/theia_methods/temporal_delta --methods tracepolicy,kernelshap,lime,ffa
```

Switch to the separate Alibi environment for unchanged native Anchors:

```bash
python experiments/revision_catalog_methods.py --case-catalog revision_audit/temporal_external/results/p1_earliest_alerts_catalog.json --output results/tmp/theia_methods/earliest_alerts --methods anchors --seeds 11,23,47
python experiments/revision_catalog_methods.py --case-catalog revision_audit/temporal_external/results/p1_temporal_delta_catalog.json --output results/tmp/theia_methods/temporal_delta --methods anchors --seeds 11,23,47
python experiments/revision_catalog_summary.py --root results/tmp/theia_methods
python scripts/verify_revision_evidence.py
```

Both cohorts have 32 cases but share 18 events (46 unique current events and seven processes). The 448 outputs all have a unique size-two core, current event plus fallback deny. They demonstrate explanation fidelity for the frozen policy, not improved detection or predecessor necessity. The fixed positive EXECUTE-to-CONNECT diagnostic has zero test occurrences; its empty catalog is retained and never retuned. FFA uses a cached complete-core backend, so its descriptive timings do not establish superiority. Saved outputs are in `results/revision/theia_chronological_methods/`.

Explanation replay requires a complete prefix, empty initial state, default transition and immutable caller-owned policy contents. Domains above18 units fail explicitly. Streaming updates requiring discarded history are rejected. Temporal guards scan retained windows; cached shared temporal summaries are not implemented.

`provenance/FROZEN_PUBLICATION_SHA256_PRE_REVISION.txt` preserves the previous publication manifest. The current `FROZEN_PUBLICATION_SHA256.txt` records this revision's executable layer, not a retrospective preregistration. Original results and the original protocol remain historical evidence. The legacy corrective gate evaluates those historical artifacts, not the new revision campaigns.
