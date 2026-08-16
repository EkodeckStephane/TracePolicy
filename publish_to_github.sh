#!/usr/bin/env bash
set -euo pipefail
repo='https://github.com/EkodeckStephane/TracePolicy.git'
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone "$repo" "$tmp/repo"
find "$tmp/repo" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -a "$source_dir"/. "$tmp/repo"/
rm -rf "$tmp/repo/.git/index.lock" 2>/dev/null || true
cd "$tmp/repo"
git add -A
if ! git diff --cached --quiet; then
  git commit -m 'Publish complete TracePolicy reproducibility materials'
  git push origin main
else
  echo 'No differences to publish.'
fi
echo 'Publication complete: https://github.com/EkodeckStephane/TracePolicy'
