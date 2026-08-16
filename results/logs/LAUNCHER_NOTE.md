# Phase 5 launcher note

Date: 2026-08-14

The frozen Docker runner image `projecta-phase5-runner:2026-08-14` was attempted first, as requested by `CODEX_EXECUTION_PROMPT.md`.

- Attempt 1: `docker build -t projecta-phase5-runner:2026-08-14 -f docker/runner/Dockerfile docker/runner` failed during `pip install` with a read timeout from `files.pythonhosted.org` while downloading dependencies.
- Attempt 2: the same build was re-run with output persisted to `results/logs/docker_build_attempt_2.log`; it exceeded the tool timeout while still in dependency download.
- Attempt 3: a background build was started with `results/logs/docker_build_attempt_3.*` logs, but a previous timed-out build process was still present. The two launcher/build processes were stopped to avoid concurrent stuck builds.

No scientific protocol files were changed. Docker Desktop was reachable from the host after startup, so the Phase 5 orchestrator was run with host Python 3.11.9:

```text
python scripts/execute_phase5.py
```

The host execution completed Docker/system preflight and pulled the pinned Suricata and Wazuh images, then stopped at `collect_datasets` because the mandatory official DARPA E3 CADETS archives and official DARPA E3 ground-truth PDF were absent. The preserved execution journal is `results/logs/execution_journal.json`.

Update after dataset materialization: the three required DARPA files were added locally, `scripts/collect_datasets.py` succeeded, and the runner image build was retried. `projecta-phase5-runner:2026-08-14` then built successfully; the successful build log is `results/logs/docker_build_after_darpa.err.log`.

Runner execution attempt 1 after the successful build did not start the scientific pipeline because PowerShell stripped quoting around the workspace path with spaces, causing Docker to return `invalid reference format` before container startup. This is a launcher quoting failure only.

Runner execution attempt 2 started correctly and completed through controlled RQ1/RQ2/RQ3/RQ4. It stopped at `real_local_lab_capture` because Docker could not resolve `deb.debian.org` while building the local gateway image and therefore could not install `tcpdump`. A later DNS check from a temporary container succeeded, so the failed local-lab capture step was retried without changing scientific files.
