#!/usr/bin/env python3
from pathlib import Path
import hashlib, sys
ROOT=Path(__file__).resolve().parents[1]
manifest=ROOT/"FROZEN_PROTOCOL_SHA256.txt"
if not manifest.exists(): raise SystemExit("Missing FROZEN_PROTOCOL_SHA256.txt")
bad=[]; n=0
for line in manifest.read_text().splitlines():
    if not line.strip(): continue
    expected, rel=line.split(None,1); rel=rel.strip(); p=ROOT/rel; n+=1
    if not p.exists():
        bad.append((rel,"MISSING",expected)); continue
    h=hashlib.sha256(p.read_bytes()).hexdigest()
    if h!=expected: bad.append((rel,h,expected))
print(f"FROZEN_FILES={n} MISMATCHES={len(bad)}")
for x in bad: print("MISMATCH",*x)
if bad: raise SystemExit(2)
