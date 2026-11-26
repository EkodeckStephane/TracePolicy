# LID-DS 2021 external evaluation — CVE-2020-23839

The source archive is retained at `data/CVE-2020-23839.zip`; raw recordings are not copied into this workspace or the editorial package. The acquisition/integrity record is `archive_manifest.json` (outer SHA-256 `93d75f271a6b470dc1e97d9705e9f0ab46f3fb05249aac569d90c79ee1b8f51d`). The outer ZIP CRC, all 1,147 nested recording ZIP CRCs, and expected member structures passed.

## Frozen run

- `frozen_protocol.json`: train/validation-only construction and policy freeze; protocol SHA-256 `cac8accd9a97e9ac6f429fbfe2ac93e6d92c61a7cc1068a97c726e7dccd9b1db`.
- `predictions_without_test_labels.json`: test syscall replay without reading test JSON metadata; prediction SHA-256 `75b5fbe0090e2a8bfb55059e789ff75462819e66e7b3eb5e6f15ff3e436f93e0`.
- `label_metrics.json`: recording-level scores joined only after the frozen predictions were hash-checked.
- `verification.json`: source, policy, predictions, and test-label coverage checks.

The policy uses syscall names only and completed `<` exits, preserving original line order and nanosecond timestamps. Histories reset at each recording and are partitioned by process/thread. Training-normal support threshold is 20. The selected action-only allowlist contains 48 actions; normal validation alert fraction is zero. The best sequence-gated candidate uses up to five immediate same-thread predecessors and has a 2.2038% normal-validation alert fraction, above the declared 1% budget.

## Test results

The test set has 750 `NORMAL`, 99 `NORMAL_AND_ATTACK`, 21 `ATTACK`, and 10 `IDLE` recordings, with 26,143,034 completed exits. The action-only policy alerts in 4/750 normal recordings (25 alerts; 2.67 alerts per normal recording-hour) and in 120/120 attack-containing recordings. The sequence-gated policy alerts in all 750 normal recordings (531,005 alerts; 56,641 per normal recording-hour) and in every attack-containing recording. Both unchanged BETH-derived policies alert in all 880 test recordings; exact string matching left `security_file_open` unmatched.

The class-folder names `normal` and `normal_and_attack` were visible in the initial archive-structure listing before freeze. They did not inform policy construction or selection. Test JSON metadata and syscall streams were first opened after the frozen policy hash was recorded. Consequently, this evaluation is not called fully blind to test-category names.

The recording metadata does not expose an unambiguous exploit interval mappable to syscall timestamps. The alert coverage above is not attack-onset detection or event recall. No syscall-level confusion matrix is calculated from recording labels. This is one controlled scenario and does not establish production efficacy or cross-scenario generalization.

## Reproduction

From the repository root, after installing the Python dependencies described in `REVISION_REPRODUCIBILITY.md`:

```powershell
python experiments/revision_lidds_outer_archive_audit.py data/CVE-2020-23839.zip --inner-crc --output results\lidds_cve_2020_23839\archive_manifest.json
python experiments/revision_lidds_evaluation.py freeze --source data/CVE-2020-23839.zip --manifest results\lidds_cve_2020_23839\archive_manifest.json --output results\lidds_cve_2020_23839
python experiments/revision_lidds_evaluation.py evaluate --source data/CVE-2020-23839.zip --manifest results\lidds_cve_2020_23839\archive_manifest.json --output results\lidds_cve_2020_23839
python experiments/revision_lidds_evaluation.py labels --source data/CVE-2020-23839.zip --manifest results\lidds_cve_2020_23839\archive_manifest.json --output results\lidds_cve_2020_23839
python experiments/revision_lidds_evaluation.py verify --source data/CVE-2020-23839.zip --manifest results\lidds_cve_2020_23839\archive_manifest.json --output results\lidds_cve_2020_23839
```

`freeze` reads only training/validation metadata and traces. `evaluate` reads test `.sc` streams without JSON labels. `labels` refuses to score if the test predictions do not match the frozen protocol and prediction hash.
