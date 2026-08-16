from collections import Counter
from trace_policy_engine import Event,reference_eval,VIOLATION,CONFLICT
from phase5b_trace_policy import TrainingProfile,P1Config,freeze_p1,DirectSubjectPolicyEvaluator,compile_p1_policy

def ev(i,a,r='process',sub='S1'):
    return Event(str(i),float(i),a,r,'process',{'subject_uuid':sub},0,'normal')

def test_direct_equals_compiled_on_known_and_unknown_sensitive_sequence():
    sel_counts=Counter({('read','file:etc','process'):100,('modify_process','process','process'):100})
    seq_counts={2:Counter({(('modify_process','process','process'),('read','modify_process')):50}),3:Counter(),4:Counter()}
    prof=TrainingProfile(sel_counts,seq_counts,200,0)
    p1=freeze_p1(prof,P1Config(2,5,128,0.005),20,500)
    direct=DirectSubjectPolicyEvaluator(p1);pol=compile_p1_policy(p1)
    trace=[]
    for e in [ev(1,'read','file:etc'),ev(2,'modify_process','process')]:
        trace.append(e);a,*_=direct.classify(e);b=reference_eval(trace,pol).alert_class in (VIOLATION,CONFLICT);assert a==b
    direct=DirectSubjectPolicyEvaluator(p1);trace=[]
    for e in [ev(1,'write','file:tmp'),ev(2,'modify_process','process')]:
        trace.append(e);a,*_=direct.classify(e);b=reference_eval(trace,pol).alert_class in (VIOLATION,CONFLICT);assert a==b
