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

The static derivative loses chronology and inherits upstream label-assisted training filtering. It is distinct from any timestamp-preserving external validation. Separate temporal acquisition/protocol instructions accompany that driver when completed; raw external data must be acquired independently.

Explanation replay requires a complete prefix, empty initial state, default transition and immutable caller-owned policy contents. Domains above18 units fail explicitly. Streaming updates requiring discarded history are rejected. Temporal guards scan retained windows; cached shared temporal summaries are not implemented.

`provenance/FROZEN_PUBLICATION_SHA256_PRE_REVISION.txt` preserves the previous publication manifest. The current `FROZEN_PUBLICATION_SHA256.txt` records this revision's executable layer, not a retrospective preregistration. Original results and the original protocol remain historical evidence. The legacy corrective gate evaluates those historical artifacts, not the new revision campaigns.
