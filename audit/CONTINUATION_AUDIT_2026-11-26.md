# Continuation audit — 26 November 2026

## Reference and artifact checks

- Author manuscript, response, and cover were rebuilt after adding the Margrave prior-art comparison.
- Final PDF checks: manuscript 24 pages; response six pages covering 18 points; cover one page; zero out-of-page text; zero unresolved references/citations.
- Rebuilt author-review archive: 1,940 members, 1,935 manifested files, three submitted references verified, zero CRC errors, zero manifest disagreements.
- The exact bundle digest and the three document digests are recorded by the author-package audit scripts in the companion workspace. This public repository does not include those documents.

## Code and saved-evidence checks

Environment: companion revision Python 3.11 environment with `pyarrow==26.0.0` and `duckdb==1.5.6`.

- `python -m pytest -q -rs`: 68 passed, zero skipped.
- `python scripts/verify_frozen_protocol_v2.py`: 71 publication-protocol files, zero mismatches.
- `python scripts/verify_revision_evidence.py`: passed; independently rechecked saved witnesses for Docker, chronological THEIA, and live proofs (2,276 total).
- `python scripts/verify_joint_union_ablation.py`: passed; 168/168 Docker unions and 11/11 controlled-fixture unions are sufficient in their joint tables; the constructed witness has two sufficient and two insufficient crossed unions.
- `git diff --check`: passed for the current documentation changes before this report was added.

These checks verify the current code and saved results. The union-ablation observations remain bounded to the specified workloads and fixtures; the constructed witness supplies a finite semantic counterexample, not a real-world frequency estimate. No independent external holdout or analyst-utility result was created in this continuation.

## Phase decision

**NO-GO remains.** R1.10 is strengthened by the direct Margrave comparison, while its full collision analysis remains incomplete. R1.18 remains open pending evidence of originality and significance. Journal fit, independent external validation, realistic version-change utility, and scalable certified solving remain unresolved.
