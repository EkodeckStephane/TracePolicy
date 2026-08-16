# Reproducibility quickstart

The full procedure is documented in `README.md`, Section 9. The minimum sequence is:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-lime.txt
python scripts/collect_datasets.py
pytest -q
bash run_all.sh
python scripts/compute_phase5_statistics_v2.py
```

For DARPA CADETS, obtain the official E3 archives using the source and target filenames in `datasets/DATASETS.md`. Keep the large archives outside Git history.

## Revision validation: explanation scaling and real Docker alerts

The post-protocol validation added after the explanation-scope audit does not replace the frozen primary results. It makes the exact explainer's operating domain explicit and uses already-collected Docker evidence.

Run the controlled scaling experiment:

```bash
python experiments/run_rq2_scaling.py --min-units 5 --max-units 18 --repeats 3
```

Outputs:

- `results/raw/rq2_scaling.csv`
- `results/summary/rq2_scaling_summary.csv`

The exact implementation is intentionally bounded at 18 explanatory units. The experiment records the exact number of canonical evaluations as well as intrinsic, SHAP, and—when the optional official LIME dependency is installed—LIME runtimes.

Run the real-bench explanation extension:

```bash
python experiments/run_rq2_local_lab_explanations.py
```

This selects 100 true-positive alerts from the already-retained local Docker workloads, balanced across `admin_probe`, `bruteforce`, `command_probe`, and `path_traversal`. It writes:

- `results/raw/rq2_local_lab_explanations.csv`
- `results/summary/rq2_local_lab_explanations_summary.csv`

To enable the optional LIME columns in environments with internet access:

```bash
python -m pip install 'lime==0.2.0.0'
python experiments/run_rq2_scaling.py --min-units 5 --max-units 18 --repeats 3
python experiments/run_rq2_local_lab_explanations.py
```

The original 32-case LIME experiment remains available through `experiments/run_rq2_lime.py` and is kept distinct from these scope-validation additions.

