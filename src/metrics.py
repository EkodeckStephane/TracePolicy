from __future__ import annotations
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, average_precision_score

def binary_metrics(y, pred, score=None):
    y=np.asarray(y,dtype=int); pred=np.asarray(pred,dtype=int)
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    out=dict(precision=float(precision_score(y,pred,zero_division=0)),recall=float(recall_score(y,pred,zero_division=0)),
             f1=float(f1_score(y,pred,zero_division=0)),fpr=float(fp/(fp+tn)) if fp+tn else float('nan'),
             tp=int(tp),tn=int(tn),fp=int(fp),fn=int(fn))
    if score is not None and len(np.unique(y))==2:
        out['auc_roc']=float(roc_auc_score(y,score)); out['auc_pr']=float(average_precision_score(y,score))
    return out
