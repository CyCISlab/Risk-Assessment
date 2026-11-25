import analysis as A, numpy as np, json, csv
from sklearn.metrics import roc_auc_score
from cvss import CVSS3, CVSS4
I=A.ITEMS; base=np.array([i['base'] for i in I]); kev=np.array([i['kev'] for i in I]).astype(int)
res={}
# 1. sensitivity sweep
V={'default':{},
 'method=conservative':{'method':'conservative'},'method=aggressive':{'method':'aggressive'},
 'no bonus/penalty':{'bonus':False},
 'CP=partial (0.5, penalty on)':{'cp':0.5},'CP=none (1.0)':{'cp':1.0},
 'SI all LOW (0.5)':{'si':0.5},'SI all HIGH (1.0)':{'si':1.0},
 'CD all LOW (0.5)':{'cd':0.5},'CD all HIGH (1.0)':{'cd':1.0},
 'BC alt (no CONTROL tier)':{'bc':'availability_only'},
 'VI/MI/CI split mapping':{'vmc':'split'},'VI/MI/CI all NONE':{'vmc':0.0},
 'LA fixed 0.5 (not mirrored)':{'la':0.5},
 'standalone IVSS (no CVSS anchor)':{'mode':'standalone','ex_kev':False},
 'standalone IVSS, no bonus/penalty':{'mode':'standalone','ex_kev':False,'bonus':False},
}
S={}
rows=[]
import pickle
for k,cfg in V.items():
    s=np.array([A.score(i,cfg) for i in I]); S[k]=s
    d=A.summarize(k,s); d={kk:(float(vv) if isinstance(vv,(np.floating,)) else vv) for kk,vv in d.items()}
    d['kev_auc']=round(roc_auc_score(kev,s),3); rows.append(d); print(d)
# 2. env baselines
def setm(v,extra):
    p=v.split('/'); head=p[0]; d={}
    for x in p[1:]:
        k,val=x.split(':',1); d[k]=val
    d.update(extra); return head+'/'+'/'.join(f'{k}:{val}' for k,val in d.items())
def env3(v): return float(CVSS3(setm(v,{'CR':'L','IR':'H','AR':'H'})).scores()[2])
def env4(v,safe):
    ex={'CR':'L','IR':'H','AR':'H'}
    if safe: ex.update({'MSI':'S','MSA':'S'})
    return float(CVSS4(setm(v,ex)).base_score)
E1=[];E2=[]
for i in I:
    if i['basis']=='v4.0':
        sec=i['meta']['sectors'] if i['meta'] else set()
        hi=bool(sec & A.R.SAFETY_HIGH_SECTORS)
        E1.append(env4(i['v4'],False)); E2.append(env4(i['v4'],hi))
    else:
        e=env3(i['v3']); E1.append(e); E2.append(e)
for k,s in [('CVSS env (CR:L/IR:H/AR:H)',np.array(E1)),('CVSS env + v4 safety (MSI/MSA:S, high-safety sectors)',np.array(E2)),('CVSS base',base)]:
    S[k]=s; d=A.summarize(k,s); d={kk:(float(vv) if isinstance(vv,np.floating) else vv) for kk,vv in d.items()}; d['kev_auc']=round(roc_auc_score(kev,s),3); rows.append(d); print(d)
# 3. hybrid vs env: agreement on escalation
bb=np.array([A.band(x) for x in base])
def bands(s): return np.array([A.band(round(x,1)) for x in s])
h=bands(S['default']); e=bands(S['CVSS env (CR:L/IR:H/AR:H)'])
he=(h>bb); ee=(e>bb)
print('hybrid escalates',he.mean(),'env escalates',ee.mean(),'both',(he&ee).mean(),'hybrid-only',(he&~ee).mean(),'env-only',(~he&ee).mean())
print('r(hybrid,env)',np.corrcoef(S['default'],S['CVSS env (CR:L/IR:H/AR:H)'])[0,1],'band agreement',(h==e).mean())
# 4. KEV top-k
for k in ['CVSS base','default','standalone IVSS (no CVSS anchor)','CVSS env (CR:L/IR:H/AR:H)']:
    s=S[k]; o=np.argsort(-s,kind='stable')
    # ties: report expected hits under random tie-breaking at cutoff
    out=[]
    for K in [100,500,1000]:
        thr=s[o[K-1]]; above=s>thr; at=s==thr; need=K-above.sum()
        exp=kev[above].sum()+ (kev[at].sum()*need/at.sum() if at.sum() else 0)
        out.append((K,round(exp,1)))
    print('KEV hits top-k',k,out,'base rate per 1000',round(kev.mean()*1000,1))
json.dump(rows,open('sweep_results.json','w'),indent=1)
np.savez('scores.npz',**{k.replace(' ','_'):v for k,v in S.items()},kev=kev,base=base)
