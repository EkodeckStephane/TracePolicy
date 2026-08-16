#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -t projecta-phase5-runner:2026-08-14 -f docker/runner/Dockerfile docker/runner
docker run --rm -it \
  -v "$PWD:/work" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --env DARPA_CADETS_TRAIN_URL --env DARPA_CADETS_TEST_URL --env DARPA_E3_GT_PDF_URL \
  -w /work projecta-phase5-runner:2026-08-14 python scripts/execute_phase5.py
