#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import numpy as np,pandas as pd,json
from scipy.stats import wilcoxon
ROOT=Path(__file__).resolve().parents[1]
RAW=ROOT/'results/raw'; STAT=ROOT/'results/statistics'; SUM=ROOT/'results/summary'
STAT.mkdir(parents=True,exist_ok=True);SUM.mkdir(parents=True,exist_ok=True)

def holm_adjust(pvals):
    p=np.asarray(pvals,float)
    n=len(p)
    order=np.argsort(p)
    adj=np.empty(n,float)
    running=0.0
    for rank,i in enumerate(order):
        val=(n-rank)*p[i]
        running=max(running,val)
        adj[i]=min(running,1.0)
    return adj

def boot_ci(x,B=10000,seed=20260816):
    x=np.asarray(x,float); rng=np.random.default_rng(seed)
    if len(x)<2:return (np.nan,np.nan)
    means=x[rng.integers(0,len(x),(B,len(x)))].mean(1)
    return tuple(np.quantile(means,[.025,.975]))

def rbc(d):
    d=np.asarray(d,float);d=d[np.isfinite(d)&(d!=0)]
    if len(d)==0:return np.nan
    ranks=pd.Series(np.abs(d)).rank(method='average').to_numpy()
    return float((ranks[d>0].sum()-ranks[d<0].sum())/ranks.sum())

tests=[]; cis=[]
def add_ci(family,label,x):
    x=np.asarray(x,float);lo,hi=boot_ci(x)
    cis.append({'family':family,'label':label,'n':len(x),'mean':float(np.mean(x)),'sd':float(np.std(x,ddof=1)) if len(x)>1 else np.nan,
                'median':float(np.median(x)),'ci95_low':lo,'ci95_high':hi})
def paired(family,label,a,b,alternative='two-sided'):
    a=np.asarray(a,float);b=np.asarray(b,float);d=a-b
    try:w=wilcoxon(a,b,alternative=alternative,zero_method='wilcox')
    except ValueError:
        tests.append({'family':family,'comparison':label,'n':len(a),'statistic':np.nan,'p_raw':1.0,'mean_delta':float(d.mean()),'rank_biserial':rbc(d)})
        return
    tests.append({'family':family,'comparison':label,'n':len(a),'statistic':float(w.statistic),'p_raw':float(w.pvalue),
                  'mean_delta':float(d.mean()),'median_delta':float(np.median(d)),'rank_biserial':rbc(d)})

# Local baseline metrics over 30 distinct seeded workloads.
local={}
for name,file in [('TracePolicy','rq5_local_lab_tracepolicy.csv'),('Suricata','rq5_local_lab_suricata.csv'),('Wazuh','rq5_local_lab_wazuh.csv')]:
    d=pd.read_csv(RAW/file).sort_values('seed');local[name]=d
    for m in ['precision','recall','f1','fpr','episode_precision','episode_recall','episode_f1']:
        add_ci('local_lab',f'{name}:{m}',d[m])
for other in ['Suricata','Wazuh']:
    for m in ['recall','f1','episode_recall','episode_f1']:
        paired('local_baseline_vs_tracepolicy',f'{other}-TracePolicy:{m}',local[other][m],local['TracePolicy'][m])

# Same-oracle explanation cost; 32 paired cases.
rq2_order=['seed','kind','target_class']
sh=pd.read_csv(RAW/'rq2_intrinsic_vs_shap.csv').sort_values([c for c in rq2_order if c in pd.read_csv(RAW/'rq2_intrinsic_vs_shap.csv',nrows=0).columns])
li=pd.read_csv(RAW/'rq2_intrinsic_vs_lime.csv').sort_values([c for c in rq2_order if c in pd.read_csv(RAW/'rq2_intrinsic_vs_lime.csv',nrows=0).columns])
add_ci('rq2_cost','intrinsic_us',sh.intrinsic_us);add_ci('rq2_cost','shap_us',sh.shap_us);add_ci('rq2_cost','lime_us',li.lime_us)
paired('rq2_cost','SHAP>Intrinsic',sh.shap_us,sh.intrinsic_us,alternative='greater')
paired('rq2_cost','LIME>Intrinsic',li.lime_us,sh.intrinsic_us,alternative='greater')

# Controlled RQ1: paired by seed against clean baseline.
r1=pd.read_csv(RAW/'rq1_local_detection.csv')
base=r1[(r1.policy_deletion_fraction==0)&(r1.trace_dropout_fraction==0)].set_index('seed').sort_index()
for (pdelf,tdrop),g in r1.groupby(['policy_deletion_fraction','trace_dropout_fraction']):
    if pdelf==0 and tdrop==0:continue
    g=g.set_index('seed').loc[base.index]
    paired('rq1_controlled_vs_clean',f'policy_del={pdelf},trace_drop={tdrop}:F1',g.f1,base.f1)

# RQ4 timing: paired repetitions only.
r4=pd.read_csv(RAW/'rq4_darpa_latency.csv')
for (mode,P),g in r4.groupby(['mode','P']):
    piv=g.pivot(index='seed',columns='engine',values='mean_us').sort_index()
    for eng in ['indexed','incremental']:
        paired('rq4_darpa_latency',f'{mode}:P={P}:{eng}<reference',piv[eng],piv.reference,alternative='less')
        add_ci('rq4_darpa_latency',f'{mode}:P={P}:{eng}:mean_us',piv[eng])

# TON learned baselines: paired seeds.
rf=pd.read_csv(RAW/'rq5_rf_test_metrics_30seeds.csv').sort_values('seed')
iff=pd.read_csv(RAW/'rq5_if_test_metrics_30seeds.csv').sort_values('seed')
for m in ['f1','auc_roc','auc_pr']:
    paired('toniot_rf_vs_if',f'RF-IF:{m}',rf[m],iff[m])
    add_ci('toniot',f'RF:{m}',rf[m]);add_ci('toniot',f'IF:{m}',iff[m])

# Holm correction within each test family.
td=pd.DataFrame(tests)
if len(td):
    td['p_holm']=np.nan;td['reject_0.05']=False
    for fam,idx in td.groupby('family').groups.items():
        q=holm_adjust(td.loc[idx,'p_raw'].to_numpy())
        td.loc[idx,'p_holm']=q;td.loc[idx,'reject_0.05']=q<.05
td.to_csv(STAT/'paired_tests_v2.csv',index=False)
pd.DataFrame(cis).to_csv(STAT/'bootstrap_ci_v2.csv',index=False)

# Deterministic DARPA detection: ONE point estimate, repetitions are timing runs.
dar=pd.read_csv(RAW/'rq5_darpa_cadets_metrics.csv')
cols=['precision','recall','f1','fpr','tp','tn','fp','fn','n','policy_rules']
point=dar.iloc[[0]][cols].copy()
point['note']='Single deterministic detection point estimate; 30 rows are timing repetitions, not independent detection replicates.'
point.to_csv(STAT/'darpa_detection_point_estimate_v2.csv',index=False)

# Consistency check: classification counts must be identical across repetitions.
for c in ['tp','tn','fp','fn','precision','recall','f1','fpr']:
    if dar[c].nunique(dropna=False)!=1:
        raise RuntimeError(f'DARPA deterministic detection value changed across repetitions: {c}')

print('WROTE',STAT/'paired_tests_v2.csv')
print('WROTE',STAT/'bootstrap_ci_v2.csv')
print('WROTE',STAT/'darpa_detection_point_estimate_v2.csv')
