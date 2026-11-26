"""Create a structure/hash manifest for one LID-DS 2021 scenario.

This pre-analysis step reads ZIP central directories only. It deliberately does
not open recording JSON metadata or syscall streams, including those in test.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

EXPECTED = {".sc", ".json", ".pcap", ".res"}
SPLITS = ("training", "validation", "test")


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def split_for(path: Path, root: Path) -> str:
    parts = path.relative_to(root).parts
    if not parts or parts[0] not in SPLITS:
        raise ValueError(f"Archive outside expected split directories: {path}")
    split = parts[0]
    expected_depth = 2 if split in {"training", "validation"} else 3
    if len(parts) != expected_depth:
        raise ValueError(f"Unexpected {split} archive depth: {path}")
    return split


def inspect_archive(path: Path, root: Path) -> dict[str, object]:
    split = split_for(path, root)
    with zipfile.ZipFile(path) as archive:
        members = [item for item in archive.namelist() if not item.endswith("/")]
        stems = {Path(item).stem for item in members if Path(item).suffix in EXPECTED}
        suffixes = {Path(item).suffix for item in members}
        stem = path.stem
        expected_members = {f"{stem}{suffix}" for suffix in EXPECTED}
        missing = sorted(expected_members - set(members))
        # The official loader expects each named recording member at ZIP root.
        root_members = {item for item in members if "/" not in item and "\\" not in item}
        missing_root = sorted(expected_members - root_members)
        if missing:
            status = "missing_expected_members"
        elif missing_root:
            status = "expected_members_not_at_archive_root"
        else:
            status = "structure_ok"
        return {
            "path": str(path),
            "split": split,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
            "archive_status": status,
            "member_count": len(members),
            "recording_member_stems": sorted(stems),
            "observed_suffixes": sorted(suffixes),
            "missing_expected_members": missing,
            "expected_members_not_at_root": missing_root,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario_dir", type=Path, help="Directory containing training/, validation/, test/")
    parser.add_argument("--output", type=Path, default=None, help="Manifest JSON path")
    args = parser.parse_args()
    root = args.scenario_dir.resolve()
    if not root.is_dir():
        raise SystemExit(f"Scenario directory does not exist: {root}")

    archives = sorted(root.glob("training/*.zip"))
    archives += sorted(root.glob("validation/*.zip"))
    archives += sorted(root.glob("test/*/*.zip"))
    if not archives:
        raise SystemExit("No ZIP files found in official training/validation/test layout")

    rows = [inspect_archive(path, root) for path in archives]
    counts = {split: sum(row["split"] == split for row in rows) for split in SPLITS}
    missing_splits = [split for split, count in counts.items() if not count]
    result = {
        "dataset": "LID-DS 2021",
        "scenario": root.name,
        "scenario_dir": str(root),
        "inspection_scope": "ZIP central directories and full-file SHA-256 only; no JSON metadata or syscall stream opened",
        "recordings_per_split": counts,
        "archives": rows,
        "status": "structure_ok" if not missing_splits and all(r["archive_status"] == "structure_ok" for r in rows) else "review_required",
        "missing_splits": missing_splits,
    }
    output = args.output or root / "lidds_structure_manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("scenario", "recordings_per_split", "status", "missing_splits")}, indent=2))
    print(f"Manifest: {output}")
    if result["status"] != "structure_ok":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
