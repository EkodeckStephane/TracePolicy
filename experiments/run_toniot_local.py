from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import numpy as np,pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.ensemble import RandomForestClassifier,IsolationForest
from sklearn.metrics import precision_score,recall_score,f1_score,confusion_matrix,roc_auc_score,average_precision_score
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from toniot_adapter import load,FC,derive_policy_from_training_normal,to_events
from trace_policy_engine import IncrementalEvaluator,VIOLATION,CONFLICT
from metrics import binary_metrics
SEEDS=json.load(open(ROOT/'config'/'seeds.json'))['seeds']

def split(D):
    y=D.label.to_numpy(int);groups=pd.util.hash_pandas_object(D[FC],index=False).astype(str).values
    sg=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=20260814);tv,te=next(sg.split(D,y,groups));sub=D.iloc[tv];sy=y[tv];sgp=groups[tv]
    sg2=StratifiedGroupKFold(n_splits=4,shuffle=True,random_state=20260815);trr,var=next(sg2.split(sub,sy,sgp));tr=tv[trr];va=tv[var]
    assert set(groups[tr]).isdisjoint(set(groups[va]));assert set(groups[tr]).isdisjoint(set(groups[te]));assert set(groups[va]).isdisjoint(set(groups[te]))
    return tr,va,te,groups

def mlmet(y,p,s): return {**binary_metrics(y,p), 'auc_roc':float(roc_auc_score(y,s)), 'auc_pr':float(average_precision_score(y,s))}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--data',default=str(ROOT/'datasets'/'seed'/'Train_Test_IoT_Modbus.csv'));args=ap.parse_args()
    out=ROOT/'results'/'raw';out.mkdir(parents=True,exist_ok=True);D=load(args.data);tr,va,te,groups=split(D);y=D.label.to_numpy(int);X=D[FC].to_numpy(float)
    pd.DataFrame([{'split':'train','n':len(tr),'positive':int(y[tr].sum()),'groups':len(set(groups[tr]))},{'split':'validation','n':len(va),'positive':int(y[va].sum()),'groups':len(set(groups[va]))},{'split':'test','n':len(te),'positive':int(y[te].sum()),'groups':len(set(groups[te]))}]).to_csv(out/'rq5_toniot_split_manifest.csv',index=False)
    pol=derive_policy_from_training_normal(D.iloc[tr]); inc=IncrementalEvaluator(pol); yy=[];pp=[];pred=[]
    for e in to_events(D.iloc[te]):
        r=inc.push(e);p=int(r.alert_class in (VIOLATION,CONFLICT));yy.append(int(e.malicious));pp.append(p);pred.append({'eid':e.eid,'truth':int(e.malicious),'pred':p,'alert_class':r.alert_class,'top':';'.join(r.top)})
    pd.DataFrame([{'split':'test',**binary_metrics(yy,pp)}]).to_csv(out/'rq5_toniot_policy_metrics.csv',index=False);pd.DataFrame(pred).to_csv(out/'rq5_toniot_policy_test_predictions.csv',index=False)
    Xtv=np.vstack([X[tr],X[va]]);ytv=np.concatenate([y[tr],y[va]])
    # Hyperparameter selection is validation-only. The frozen test split is not inspected here.
    rfgrid=[]
    for n_estimators in (50,100,200):
      for max_depth in (None,8,16):
       for min_leaf in (1,2,5):
        m=RandomForestClassifier(n_estimators=n_estimators,max_depth=max_depth,min_samples_leaf=min_leaf,class_weight='balanced',random_state=SEEDS[0],n_jobs=-1).fit(X[tr],y[tr])
        sv=m.predict_proba(X[va])[:,1];pv=(sv>=.5).astype(int);rfgrid.append({'val_f1':f1_score(y[va],pv,zero_division=0),'n_estimators':n_estimators,'max_depth':-1 if max_depth is None else max_depth,'min_samples_leaf':min_leaf})
    rg=pd.DataFrame(rfgrid).sort_values(['val_f1','n_estimators','max_depth','min_samples_leaf'],ascending=[False,True,True,True]).reset_index(drop=True);rg.to_csv(out/'rq5_rf_validation_grid.csv',index=False);best=rg.iloc[0];bd=None if int(best.max_depth)==-1 else int(best.max_depth)
    rfrows=[]
    for seed in SEEDS:
        m=RandomForestClassifier(n_estimators=int(best.n_estimators),max_depth=bd,min_samples_leaf=int(best.min_samples_leaf),class_weight='balanced',random_state=seed,n_jobs=-1).fit(Xtv,ytv);s=m.predict_proba(X[te])[:,1];p=(s>=.5).astype(int);rfrows.append({'seed':seed,'n_estimators':int(best.n_estimators),'max_depth':-1 if bd is None else bd,'min_samples_leaf':int(best.min_samples_leaf),**mlmet(y[te],p,s)})
    pd.DataFrame(rfrows).to_csv(out/'rq5_rf_test_metrics_30seeds.csv',index=False)
    tune=IsolationForest(n_estimators=100,random_state=SEEDS[0],n_jobs=-1,contamination='auto').fit(X[tr][y[tr]==0]);trs=-tune.score_samples(X[tr][y[tr]==0]);vs=-tune.score_samples(X[va]);grid=[]
    for q in [.01,.02,.05,.10,.20,.30]:
        thr=float(np.quantile(trs,1-q));p=(vs>=thr).astype(int);grid.append((f1_score(y[va],p,zero_division=0),q,thr))
    grid.sort(reverse=True);q=grid[0][1];pd.DataFrame(grid,columns=['val_f1','tail_quantile','threshold_train_normal']).to_csv(out/'rq5_if_validation_grid.csv',index=False)
    ifrows=[]
    for seed in SEEDS:
        m=IsolationForest(n_estimators=100,random_state=seed,n_jobs=-1,contamination='auto').fit(Xtv[ytv==0]);tvs=-m.score_samples(Xtv[ytv==0]);s=-m.score_samples(X[te]);thr=float(np.quantile(tvs,1-q));p=(s>=thr).astype(int);ifrows.append({'seed':seed,'tail_quantile':q,'threshold':thr,**mlmet(y[te],p,s)})
    pd.DataFrame(ifrows).to_csv(out/'rq5_if_test_metrics_30seeds.csv',index=False)
if __name__=='__main__':main()
