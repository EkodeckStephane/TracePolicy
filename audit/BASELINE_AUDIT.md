# Baseline audit — 26 November 2026

## Reference state

- Repository: `https://github.com/EkodeckStephane/TracePolicy`
- Branch: `revision/cose-2026-review`
- Commit: `37221772b808afb429f246b8793edf78e95f2819`
- GitHub branch API and local `HEAD` agreed on this SHA on 2026-11-26. The last recorded GitHub Actions run (45800456174) is completed/success on the same SHA.
- Local checkout was clean before audit files were added. This audit is tied to that pre-audit commit; the new report files are uncommitted working changes.
- The current public branch is a software/science-evidence snapshot. The manuscript, prior submission, reviewer PDF, response and cover letter are companion files in the local author-review workspace, not GitHub branch content.

The exact list of 1,972 Git-tracked files and their SHA-256 values is `BASELINE_MANIFEST.json`. The public freeze in `FROZEN_PUBLICATION_SHA256.txt` covers 71 selected implementation/configuration files and currently verifies with 0 mismatches. These two manifests have different scopes. Raw datasets, ignored environments and temporary files are outside the Git baseline hash inventory.

## Inputs examined

1. Current GitHub revision branch and exact commit, including README, tests, pinned requirement files, CI workflow, source, experiment drivers, result records and provenance manifests.
2. Local current manuscript source/PDF, original submitted PDF/TeX, original reviewer report and response/cover letter sources.
3. Current cross-document coherence audit (24 November 2026), continuation/risk protocol, review matrix, claim-evidence matrix, reference audit, package verification and public commit/CI record.
4. Earlier standalone audit and primary-source positioning note. The standalone independent review explicitly says it was not a complete theorem proof audit or an independent journal acceptance review. No separate comprehensive document titled as the latest Q1 audit was located in the inspected audit directories.
5. Dataset and artifact records for Docker/local lab, BETH, THEIA, LID-DS CVE-2020-23839, DEDALE feasibility, distributed runs, and saved ablation evidence. The raw LID-DS archive exists at `D:\dataset\CVE-2020-23839.zip` (1,495,561,854 bytes); it was not reread or re-extracted in this baseline pass.
6. Current official Elsevier Computers & Security journal page, which states an AI/ML moratorium as of early 2024 for submissions featuring AI/ML as significant components. Whether this policy applies to the present deterministic explicit-policy/XAI article is unresolved and is a potentially blocking journal-fit issue. The ScienceDirect author-guide endpoint returned HTTP 403 in this audit; its current detailed instructions remain unverified.

## Reproduction and checks actually performed

See `BASELINE_TEST_REPORT.json`. In brief: 67 repository tests pass in a temporary Python 3.11 environment with pinned `pyarrow==26.0.0` and `duckdb==1.5.6`; 71 publication hashes verify; the saved evidence verifier rechecks prior Anchor/FFA/THEIA and live proof records. The author-review PDF/package check from the companion workspace reports 23 manuscript pages, all 18 response points, no undefined references, and no out-of-page text.

These are verification/reproduction checks of software and archived outputs. Full BETH, LID-DS, THEIA, Docker, distributed, or baseline campaigns were not rerun. The raw data are external or intentionally excluded, and the ablation driver writes into an existing result directory; preserving that archived directory takes precedence over an unisolated rerun. No complete clean-clone dependency rebuild or clean LaTeX build was performed. The exact current environment lacks SHAP, LIME, Alibi, DuckDB and PyArrow; the temporary test environment supplied only DuckDB/PyArrow. Thus a passing core test suite does not verify all optional baselines or reproduction paths.

## Scientific and editorial baseline decision

**NO-GO.** This is a baseline audit, not a claim that the work is scientifically invalid. At least four essential matters remain open: journal-fit interpretation under the current AI/ML moratorium; full-text originality collision analysis; formal composability of the separated explanation families; and an untouched independent holdout for any generalization claim. Current paired results show joint event-rule cores on the selected Docker cases and fixtures, but they do not establish superiority or general utility. The exact solver remains bounded at 18 units; the scalable certificate route is not established. Realistic policy-version diagnostic value and analyst utility remain unverified.

Use the dated roadmap in `REVISION_ROADMAP.md`. No results are reclassified as confirmatory, and no historical result files were changed by this phase-0 check.
