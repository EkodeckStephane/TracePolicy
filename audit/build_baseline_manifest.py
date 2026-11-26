"""Create a content-hash inventory tied to the clean baseline Git commit."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "audit" / "BASELINE_MANIFEST.json"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> None:
    commit = git("rev-parse", "HEAD")
    branch = git("branch", "--show-current")
    tracked_dirty = any(
        subprocess.run(["git", *args], cwd=ROOT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL).returncode
        for args in (("diff", "--quiet", "HEAD", "--"),
                     ("diff", "--cached", "--quiet", "HEAD", "--"))
    )
    if tracked_dirty:
        raise SystemExit("Tracked baseline files changed; capture from the clean baseline commit")
    paths = git("ls-files", "-z").split("\0")
    entries = {}
    for rel in filter(None, paths):
        payload = (ROOT / Path(rel)).read_bytes()
        entries[rel.replace("\\", "/")] = hashlib.sha256(payload).hexdigest()
    frozen = ROOT / "FROZEN_PUBLICATION_SHA256.txt"
    frozen_count = sum(bool(line.strip()) for line in frozen.read_text().splitlines())
    payload = {
        "baseline_commit": commit,
        "branch": branch,
        "baseline_commit_tracked_tree_clean": True,
        "untracked_audit_outputs_excluded": True,
        "tracked_files": len(entries),
        "tracked_file_sha256": entries,
        "publication_freeze_manifest": "FROZEN_PUBLICATION_SHA256.txt",
        "publication_freeze_entries": frozen_count,
        "capture_scope": "Git-tracked checkout files at the stated commit; external datasets, ignored environments, and untracked files are excluded.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("baseline_commit", "branch", "tracked_files", "publication_freeze_entries")}, indent=2))


if __name__ == "__main__":
    main()
