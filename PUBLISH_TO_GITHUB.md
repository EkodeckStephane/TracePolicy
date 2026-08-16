# Publish this prepared repository to GitHub

Target repository: `https://github.com/EkodeckStephane/TracePolicy`

The ChatGPT GitHub connector available during preparation was authenticated as another GitHub account and therefore was not used to publish this repository.

If the target repository is empty, from this directory run:

```bash
git init
git add .
git commit -m "Initial TracePolicy reproducibility release"
git branch -M main
git remote add origin https://github.com/EkodeckStephane/TracePolicy.git
git push -u origin main
```

If GitHub asks for authentication, authenticate as **EkodeckStephane** using your usual Git credential manager or a personal access token with repository write permission.

After the push, verify at least:

- `README.md` renders correctly;
- `src/trace_policy_engine.py` is present;
- `results/statistics/` contains the retained statistical outputs;
- `phase5b/` is present;
- `datasets/DATASETS.md` documents acquisition of large CADETS files;
- no manuscript PDF/LaTeX source or internal manuscript-audit report is present.
