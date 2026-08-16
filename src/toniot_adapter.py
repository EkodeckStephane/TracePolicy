from __future__ import annotations
import pandas as pd, numpy as np
from trace_policy_engine import *
FC=['FC1_Read_Input_Register','FC2_Read_Discrete_Value','FC3_Read_Holding_Register','FC4_Read_Coil']

def load(path):
    df=pd.read_csv(path)
    df['date']=df['date'].astype(str).str.strip(); df['time']=df['time'].astype(str).str.strip()
    df['dt']=pd.to_datetime(df['date']+' '+df['time'],format='%d-%b-%y %H:%M:%S',errors='coerce')
    return df

def to_events(df):
    ev=[]
    base=df['dt'].min()
    for i,row in df.iterrows():
        ts=(row['dt']-base).total_seconds() if pd.notna(row['dt']) else float(i)
        attrs={c:int(row[c]) for c in FC}
        ev.append(Event(f'TON{i}',float(ts),'modbus_read','modbus','device',attrs,int(row['label']),str(row['type'])))
    return ev

def derive_policy_from_training_normal(train_df,version=1):
    normal=train_df[train_df.label==0]
    if len(normal)==0: raise ValueError('no normal records in training')
    rules=[]
    # Conservative signature: each register outside observed normal range is a deny indicator.
    # We use extrema rather than test-derived thresholds; they are computed only from training-normal.
    for j,c in enumerate(FC,1):
        lo=int(normal[c].min()); hi=int(normal[c].max())
        rules.append(Rule(f'D_{c}_LOW',100,DENY,Selector('modbus_read','modbus','device'),Guard(((c,'<',lo),))))
        rules.append(Rule(f'D_{c}_HIGH',100,DENY,Selector('modbus_read','modbus','device'),Guard(((c,'>',hi),))))
    # Explicit allow for in-range Modbus reads, lower priority.
    comps=[]
    for c in FC:
        lo=int(normal[c].min()); hi=int(normal[c].max()); comps.extend([(c,'>=',lo),(c,'<=',hi)])
    rules.append(Rule('A_MODBUS_NORMAL_RANGE',10,ALLOW,Selector('modbus_read','modbus','device'),Guard(tuple(comps))))
    return PolicyVersion('TON_MODBUS',version,tuple(rules))
