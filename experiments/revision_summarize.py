"""Summarize raw revision measurements without treating repeated fixtures as independent."""
from pathlib import Path
import json
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]

def main():
    folder=ROOT/'results/revision'
    rows=json.loads((folder/'benchmark.json').read_text())
    df=pd.DataFrame(rows); df.to_csv(folder/'benchmark.csv',index=False)
    good=df[df.status=='ok']
    summary=good.groupby(['case','method'],as_index=False).agg(runs=('status','size'),sufficient_rate=('sufficient','mean'),minimal_rate=('minimal','mean'),core_size_min=('size','min'),core_size_max=('size','max'),total_s_median=('total_s','median'),total_s_min=('total_s','min'),total_s_max=('total_s','max'))
    summary.to_csv(folder/'benchmark_by_case_method.csv',index=False)
    lime=good[good.method=='LIME'].copy()
    lime.groupby('case',as_index=False).agg(runs=('status','size'),minimal_rate=('minimal','mean'),local_score_min=('local_training_score','min'),local_score_max=('local_training_score','max'),full_domain_mse_min=('full_domain_surrogate_mse','min'),full_domain_mse_max=('full_domain_surrogate_mse','max')).to_csv(folder/'lime_sensitivity_summary.csv',index=False)
    (folder/'nonminimal_examples.json').write_text(json.dumps([r for r in rows if r['status']=='ok' and not r['minimal']],indent=2),encoding='utf-8')
    print(summary[['case','method','runs','sufficient_rate','minimal_rate','core_size_min','core_size_max']].to_string(index=False))
    lab=folder/'local_lab/rq2_local_lab_explanations.csv'
    if lab.exists():
        d=pd.read_csv(lab)
        columns=['n_units','intrinsic_core_size','intrinsic_sufficient','intrinsic_minimal','shap_sufficient','shap_minimal','lime_sufficient','lime_minimal','intrinsic_us','shap_setup_us','shap_us','shap_selection_certification_us','shap_total_us','lime_setup_us','lime_us','lime_selection_certification_us','lime_total_us','shap_jaccard_with_core','lime_jaccard_with_core']
        d.groupby('scenario')[columns].mean().to_csv(folder/'local_lab/corrected_summary.csv')
if __name__=='__main__': main()
