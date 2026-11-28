# LIME sensitivity reproduction

**Date:** 2026-11-28  
**Purpose:** Reproduce the 486-configuration LIME sensitivity analysis cited in reviewer response R1.3.

## Result

The fresh run matched all 486 historical configurations on every stable output field. All 486 completed successfully: nine controlled fixtures, 54 configurations per fixture. The nine rows in the recorded sensitivity summary were recalculated from row-level output and matched.

Exactly one output was sufficient but nonminimal: `temporal_seq`, seed 23, 128 samples, kernel-width scale 0.5, background retention probability 0.25. It selected the four units `{e:0,e:1,e:2,r:SEQ}`; the exact full-domain audit confirms that `e:1` is redundant. The stored deletion checks for all four selected units were re-evaluated against the fresh truth table, including their counterexample masks.

## Reproduction

Using the project environment and the frozen inputs:

```powershell
environment\Scripts\python.exe experiments\revision_explanation_benchmark.py --output results/revision/lime_reproduction_2026-11-28
environment\Scripts\python.exe audit\verify_lime_sensitivity_reproduction.py
```

The run manifest records Python 3.11.9, LIME 0.2.0.1, NumPy 2.4.6, SciPy 1.17.1, scikit-learn 1.9.0, and SHAP 0.50.0. The verification JSON records hashes for the script, historical inputs, fresh outputs, case study and environment.

## Scope

This is computational reproduction using the same implementation, frozen nine fixtures and random seeds. It verifies the reported sensitivity result and saved witnesses; it is not an independent reimplementation of LIME and does not establish behavior on independent security instances or settle the eligibility of other explainers.
