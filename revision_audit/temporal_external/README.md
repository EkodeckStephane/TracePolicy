# Timestamp-preserving external THEIA replay

The acquisition uses the public hosted **chronological Parquet derivative**, not raw DARPA CDM and not the timestamp-free MAGIC graph. Immutable source revision: `690e8889c36429db1f62da22ec7ac06254d76e6a` of [alafage/darpa_tc_e3_theia](https://huggingface.co/datasets/alafage/darpa_tc_e3_theia/tree/690e8889c36429db1f62da22ec7ac06254d76e6a). The source README identifies DARPA E3 and REAPr label revisions. The source table contains44,408,090rows with true nanosecond timestamps, event UUIDs, operations and graph endpoints. No fabricated timestamps or deduplicated static-edge chronology is introduced.

Required scientific qualification: this is cross-representation/process-local verification on an engagement familiar from previous static analyses. Prior source metadata choices were published in branch `revision/cose-2026-review`, commit `e3d2ab2`, before the temporal test decisions were generated. Labels were acquired only after policy freeze. This does not make attack-generation provenance independent of the prior THEIA engagement.

## Acquisition

Download the following four files from the pinned source using URLs of the form:

`https://huggingface.co/datasets/alafage/darpa_tc_e3_theia/resolve/690e8889c36429db1f62da22ec7ac06254d76e6a/FILENAME?download=true`

| File | Bytes | SHA256 |
|---|---:|---|
| event_table.parquet |535829401|08c006812b25b56c0e1f1e3fbceac144027fcee43f1adc81cd92491497f570e1|
| process_node_table.parquet |10636043|69a057f2fce1da35d4f8c22e4ee8b73ce2fd5c14a02689bc123c67d29a08543b|
| reapr_edge_labels.parquet |494650|c77aa8a99386043aac42524c12527c9653c508d8d628a6474c380ad5862d80d8|
| reapr_node_labels.parquet |2914|4ec8b53b9507f47dc6afb1917ef4fd13ed1dca7007744dcbd97686ed8e54f860|

The driver checks every source SHA before use. Raw Parquet and the temporary DuckDB database are excluded from public Git; the acquisition metadata, immutable choices, freeze, results and bounded catalogs are public evidence. On this machine, normalization produced a2.3GB database; allow additional scratch disk and memory for joins/sorts.

One initial resumed acquisition incorrectly combined a footer probe with an active append download. `acquisition_repair.json` records the error and restoration boundary; the final complete file subsequently matched the source's full SHA256. No event rows from the corrupted intermediate file were analyzed. A footer probe must always stay in a separate file. Use one download writer per destination.

## Reproduce

From the code repository root (or the revision's `code/` directory), with Python3.11 and the main revision environment:

```powershell
python -m pip install -r requirements-temporal-revision.txt
python experiments/revision_temporal_external.py prepare --data-dir PATH_TO_PARQUET --output PATH_TO_RESULTS
python experiments/revision_temporal_external.py evaluate --data-dir PATH_TO_PARQUET --output PATH_TO_RESULTS
python experiments/revision_temporal_external.py labels --data-dir PATH_TO_PARQUET --output PATH_TO_RESULTS
python experiments/revision_temporal_external.py verify --data-dir PATH_TO_PARQUET --output PATH_TO_RESULTS
python -m pytest tests/test_temporal_external.py -q
```

For a genuinely prospective local repetition, acquire/open labels only after `prepare` writes `frozen.json`. The six training action selectors and at most three predecessors are selected using training frequencies only; validation is descriptive. All partitions are based on60%/80% of unlabelled wall-clock range, not graph-training filenames. Label metadata/sample UUIDs inspected in the earlier MAGIC analysis do not enter these rules. The driver records expected hashes and rejects mismatch.

Actor normalization follows the primary PIDSMaker CDM transformation: its explicit `edge_reversed` list includes EXECUTE, OPEN, READ and receive operations. Recover the process endpoint on the corresponding side and verify both index and hash against `process_node_table`. All44,408,090source rows pass that check. Histories are true same-process consecutive observations, ordered by nanosecond timestamp and original row; contexts carry over partition boundaries.

## Interpretation

Train19,013,056events; validation11,551,421; test13,843,613. P0 is a six-action allow list with fallback deny. P1 replaces those allows by guards on at most three training-supported predecessor actions. P2 is a separately frozen diagnostic EXECUTE→CONNECT consecutive-sequence deny, without test tuning.

P0 flags2,136,620test rows; P1 flags2,658,998, including522,378temporal changes. The fixed P2 positive sequence fires **zero** times on test. No replacement sequence is chosen after that null result.

There are32earliest P1 alerts and32earliest P1–P0 deltas, with18overlapping current events:64catalog cases represent46unique events and7processes. They are deterministic case cohorts, not64independent threats. Bounded two-event prefixes include all active guard memory and are explicitly the explanation instances; no state atoms or older active temporal dependence are silently truncated. Positive-retention minimal cores for an unexpected predecessor may collapse to current event plus fallback deny. This does not establish a positive predecessor-containing external minimal cause; the empty P2 cohort preserves that limitation.

Labels are REAPr-derived attack edge/process identifiers. Event scores use UUID membership as a proxy; process scores aggregate subject-process alert rows among test-active processes. Unlisted keys are treated negative; contaminated identities are excluded from scoring. Coverage and unmatched keys are reported, so none is represented as exhaustive official event truth. Training construction does not use labels and may contain attacks. P0/P1 ablation must preserve unfavorable tradeoffs and large false-positive counts.

Final scored results exclude two contaminated test-event rows and one contaminated active process. Out of68,922distinct REAPr attack-edge UUIDs,68,025match the whole chronology and66,221match test;897are absent from the hosted event representation. All125attack-process UUIDs match the process table,67are active in test. Duplicate test-event UUID count is zero. Exact label identity audit is in `results/detection_metrics.json`.

| Unit | Policy | TP | FP | FN | TN | F1 |
|---|---|---:|---:|---:|---:|---:|
| Event UUID proxy |P0|63818|2072800|2403|11704590|0.057941593|
| Event UUID proxy |P1|63864|2595132|2357|11182258|0.046868928|
| Active subject-process |P0|64|67406|3|6993|0.001895257|
| Active subject-process |P1|66|74381|1|18|0.001771479|

P1recovers46positive event rows while adding522,332false-positive rows. This is an unfavorable specificity tradeoff; temporal policy expressiveness does not establish practical detection improvement. P2matches P0because its fixed positive sequence never fires. Results preserve all three policies.

`results/semantic_verification.json` compares all158observed action/predecessor configurations for all three policies through canonical reference, indexed and incremental evaluators; zero class/top divergences. Those configurations represent13,843,613test rows by semantic equivalence, not13million independently replayed Python executions. The family contains no state atoms and only current-action/length2guards, which makes grouping exact for this scope.

`results/normalization_identity_audit.json` confirms279,369unique nonnull process indexes, hashes and UUIDs, and44,408,090distinct original row IDs after normalization. Process duplicates or normalization multiplication now fail before a result is accepted. Node/edge invalid UUIDs and conflicting label assignments likewise withhold metrics; the actual labels pass both checks. Seven miniature-fixture tests exercise nanosecond order, reversed actor direction, boundary history, label-free stages, hash rejection and identity failures. These fixtures test software behavior only and are never represented as external experimental observations.

Primary references:

- [DARPA E3 source description](https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md).
- [PIDSMaker direction transformation](https://github.com/ubc-provenance/PIDSMaker/blob/main/dataset_preprocessing/darpa_tc/create_database_e3.py) and [operation direction list](https://github.com/ubc-provenance/PIDSMaker/blob/main/pidsmaker/utils/dataset_utils.py); copied source files and hashes identify the exact audit evidence.
- [REAPr ground truth](https://bitbucket.org/sts-lab/reapr-ground-truth/src/main/), node revision `c33e624caf6ef47d4cdda180fc26b8c3d09a65b0`, edge revision `9c3a48ea0b8b49c13935dbc7c1d2fbccc9e759f8` according to the hosted README.
- Liu et al., *What We Talk About When We Talk About Logs: Understanding the Effects of Dataset Quality on Endpoint Threat Detection Research*, IEEE SP2025, DOI [10.1109/SP61157.2025.00112](https://doi.org/10.1109/SP61157.2025.00112).
