"""KEV and CISA SSVC (Vulnrichment) validation for Table corpus-validation.
Run after run_all.py (needs scores.npz). Fetch SSVC with fetch_ssvc.py first."""
import json, numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
import analysis as A
z=np.load('scores.npz'); kev=z['kev']; ss=json.load(open('ssvc.json'))
K={'CVSS base':'CVSS_base','Hybrid balanced':'default','Hybrid conservative':'method=conservative','Hybrid aggressive':'method=aggressive',
   'Hybrid no process proxy':'VI/MI/CI_all_NONE','Standalone IVSS':'standalone_IVSS_(no_CVSS_anchor)','CVSS environmental':'CVSS_env_(CR:L/IR:H/AR:H)'}
rng=np.random.default_rng(0)
def boot(y,s,ref,B=2000):
    P=np.where(y==1)[0];N=np.where(y==0)[0];d=[]
    for _ in range(B):
        i=np.r_[rng.choice(P,len(P)),rng.choice(N,len(N))]; d.append(roc_auc_score(y[i],s[i])-roc_auc_score(y[i],ref[i]))
    return np.percentile(d,[2.5,97.5])
m=np.array([i['cve'] in ss for i in A.ITEMS]); Im=[i for i in A.ITEMS if i['cve'] in ss]
ti=np.array([ss[i['cve']]['Technical Impact']=='total' for i in Im]).astype(int)
out={}
for name,k in K.items():
    s=z[k]; r={'KEV_AUC':round(roc_auc_score(kev,s),3),'TI_AUC':round(roc_auc_score(ti,s[m]),3)}
    if name!='CVSS base':
        r['KEV_diff_CI']=[round(x,3) for x in boot(kev,s,z['CVSS_base'])]
        r['TI_diff_CI']=[round(x,3) for x in boot(ti,s[m],z['CVSS_base'][m],500)]
    out[name]=r; print(name,r)
keys=['AV','AC','PR','UI','C','I','A']
X=np.array([[1.0 if i['m'].get(k)==v else 0.0 for k in keys for v in ['N','A','L','P','H','R']] for i in Im])
p=cross_val_predict(LogisticRegression(max_iter=2000),X,ti,cv=10,method='predict_proba')[:,1]
ph=cross_val_predict(LogisticRegression(max_iter=2000),np.c_[X,z['default'][m]],ti,cv=10,method='predict_proba')[:,1]
out['vector-only TI_AUC']=round(roc_auc_score(ti,p),3); out['vector+hybrid TI_AUC']=round(roc_auc_score(ti,ph),3)
print('vector-only',out['vector-only TI_AUC'],'vector+hybrid',out['vector+hybrid TI_AUC'],'n_kev',int(kev.sum()),'n_ssvc',int(m.sum()))
json.dump(out,open('validation_results.json','w'),indent=1)
