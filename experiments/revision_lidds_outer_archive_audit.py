"""Audit the downloaded LID-DS scenario ZIP without extracting its payload.

Only ZIP central directories, archive bytes, and CRC checks are read. Recording
JSON metadata is never opened, so this can run before test-label inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import zipfile

EXPECTED_SUFFIXES = (".json", ".sc", ".pcap", ".res")
EXPECTED_SPLITS = {"training", "validation", "test"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inner-crc", action="store_true", help="Decompress and CRC-check every member in every recording ZIP")
    args = parser.parse_args()
    outer_path = args.archive.resolve()

    rows: list[dict[str, object]] = []
    outer = zipfile.ZipFile(outer_path)
    outer_bad_member = outer.testzip()
    infos = [i for i in outer.infolist() if not i.is_dir()]
    nested = [i for i in infos if i.filename.lower().endswith(".zip") and not i.filename.startswith("__MACOSX/")]
    macos_aux = [i.filename for i in infos if i.filename.startswith("__MACOSX/") or PurePosixPath(i.filename).name == ".DS_Store"]
    aggregate_uncompressed = Counter()
    structure_errors: list[dict[str, object]] = []
    split_counts = Counter()
    for item in nested:
        parts = PurePosixPath(item.filename).parts
        if len(parts) == 3 and parts[0] == "CVE-2020-23839" and parts[1] in {"training", "validation"}:
            split = parts[1]
        elif len(parts) == 4 and parts[0:2] == ("CVE-2020-23839", "test") and parts[2] in {"normal", "normal_and_attack"}:
            split = "test"
        else:
            split = "unexpected_path"
        split_counts[split] += 1
        nested_bytes = outer.read(item)
        nested_zip_hash = digest(nested_bytes)
        expected = {PurePosixPath(item.filename).stem + suffix for suffix in EXPECTED_SUFFIXES}
        error = None
        member_rows = []
        try:
            with zipfile.ZipFile(io.BytesIO(nested_bytes)) as recording:
                members = [m for m in recording.infolist() if not m.is_dir()]
                names = {m.filename for m in members}
                roots = {m.filename for m in members if "/" not in m.filename and "\\" not in m.filename}
                missing = sorted(expected - roots)
                extra = sorted(names - expected)
                for member in members:
                    aggregate_uncompressed[member.filename.rsplit(".", 1)[-1].lower()] += member.file_size
                if missing or extra or len(members) != len(EXPECTED_SUFFIXES):
                    error = {"missing_root_members": missing, "unexpected_members": extra}
                if args.inner_crc:
                    bad = recording.testzip()
                    if bad is not None:
                        error = {"inner_crc_error": bad, **(error or {})}
                member_rows = [{"name": m.filename, "bytes": m.file_size, "crc32": f"{m.CRC:08x}"} for m in members]
        except (zipfile.BadZipFile, OSError, EOFError) as exc:
            error = {"nested_zip_error": repr(exc)}
        row = {
            "path": item.filename,
            "split": split,
            "outer_member_bytes": item.file_size,
            "outer_member_crc32": f"{item.CRC:08x}",
            "nested_zip_sha256": nested_zip_hash,
            "member_count": len(member_rows),
            "members": member_rows,
            "error": error,
        }
        rows.append(row)
        if error:
            structure_errors.append({"path": item.filename, "error": error})

    result = {
        "dataset": "LID-DS 2021",
        "scenario": "CVE-2020-23839",
        "source_archive": str(outer_path),
        "source_bytes": outer_path.stat().st_size,
        "source_sha256": hash_file(outer_path),
        "audited_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Archive names, byte counts, SHA-256, nested ZIP member structure and CRC checks; no recording JSON contents or syscall streams opened.",
        "outer_crc_error": outer_bad_member,
        "outer_entry_count": len(outer.infolist()),
        "outer_file_count": len(infos),
        "nested_recording_zip_count": len(nested),
        "nested_recording_zip_bytes": sum(i.file_size for i in nested),
        "recordings_per_split": {k: split_counts.get(k, 0) for k in sorted(EXPECTED_SPLITS | {"unexpected_path"})},
        "nested_member_uncompressed_bytes_by_suffix": dict(aggregate_uncompressed),
        "auxiliary_macos_entry_count": len(macos_aux),
        "auxiliary_macos_entries_sample": macos_aux[:30],
        "inner_crc_checked": args.inner_crc,
        "structure_errors": structure_errors,
        "status": "pass" if outer_bad_member is None and not structure_errors and not split_counts.get("unexpected_path") and all(split_counts.get(k, 0) for k in EXPECTED_SPLITS) else "review_required",
        "recordings": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("source_bytes", "source_sha256", "outer_crc_error", "nested_recording_zip_count", "recordings_per_split", "nested_member_uncompressed_bytes_by_suffix", "auxiliary_macos_entry_count", "inner_crc_checked", "structure_errors", "status")}, indent=2))
    print(f"Manifest: {args.output}")
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
