# Protocol provenance

`FROZEN_PROTOCOL_SHA256_ORIGINAL.txt` records the 40-file protocol freeze created before the 16 August 2026 disclosure/scaling revision. It is retained unchanged as a historical record and is **not** the manifest to run against the current tree: two entries were superseded by the publication revision (`formal/L5_Phase4_Formal_Specification.tex` and `src/trace_policy_engine.py`).

The current executable/configuration layer is frozen by the root `FROZEN_PUBLICATION_SHA256.txt`. The engine revision is documentation-only in `min_explain_bruteforce` (the executable AST is unchanged after docstrings are stripped); the current formal specification explicitly states the brute-force complexity and 18-unit ceiling. Additional scaling and real-Docker RQ2 experiments extend validation without rewriting the historical freeze.

Verify the publication state with:

```bash
python scripts/verify_frozen_protocol_v2.py
python scripts/corrective_gate_v2.py
pytest -q
```

Git commit/tree object IDs provide repository-wide content integrity for each published revision.
