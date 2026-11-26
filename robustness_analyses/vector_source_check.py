import sys,os,json,csv
sys.path.insert(0,os.getcwd())
import numpy as np, analysis as A
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
rows={r['CVE_Number']:r for r in csv.DictReader(open(os.path.join(A.DATA,'cve_scores_extracted.csv'),encoding='utf-8',errors='replace'))}
def src(it):
    r=rows[it['cve']]; return r['v4_source'] if it['basis']=='v4.0' else r['v3_source']
ss=json.load(open('ssvc.json'))
rng=np.random.default_rng(0)
def run(name,I):
    base=np.array([i['base'] for i in I]); kev=np.array([i['kev'] for i in I]).astype(int)
    hy=np.array([A.score(i,{}) for i in I]); sa=np.array([A.score(i,{'mode':'standalone','ex_kev':False}) for i in I])
    out={'n':len(I),'kev':int(kev.sum())}
    for k,s in [('hybrid',hy),('standalone',sa)]:
        bb=np.array([A.band(x) for x in base]); sb=np.array([A.band(round(x,1)) for x in s])
        out[k]={'esc':round((sb>bb).mean()*100,1),'deesc':round((sb<bb).mean()*100,1),'r':round(float(np.corrcoef(base,s)[0,1]),3)}
    if kev.sum()>=10:
        out['KEV_AUC']={'cvss':round(roc_auc_score(kev,base),3),'hybrid':round(roc_auc_score(kev,hy),3),'standalone':round(roc_auc_score(kev,sa),3)}
        P=np.where(kev==1)[0];N=np.where(kev==0)[0];dd=[]
        for _ in range(1000):
            j=np.r_[rng.choice(P,len(P)),rng.choice(N,len(N))];dd.append(roc_auc_score(kev[j],hy[j])-roc_auc_score(kev[j],base[j]))
        out['KEV_diff_CI']=[round(x,3) for x in np.percentile(dd,[2.5,97.5])]
    m=np.array([i['cve'] in ss for i in I])
    if m.sum()>100:
        ti=np.array([ss[i['cve']]['Technical Impact']=='total' for i in I if i['cve'] in ss]).astype(int)
        keys=['AV','AC','PR','UI','C','I','A']
        X=np.array([[1.0 if i['m'].get(k)==v else 0.0 for k in keys for v in ['N','A','L','P','H','R']] for i in I])[m]
        pv=cross_val_predict(LogisticRegression(max_iter=2000),X,ti,cv=10,method='predict_proba')[:,1]
        ph=cross_val_predict(LogisticRegression(max_iter=2000),np.c_[X,hy[m]],ti,cv=10,method='predict_proba')[:,1]
        out['SSVC']={'n':int(m.sum()),'cvss':round(roc_auc_score(ti,base[m]),3),'hybrid':round(roc_auc_score(ti,hy[m]),3),'vec':round(roc_auc_score(ti,pv),3),'vec+hy':round(roc_auc_score(ti,ph),3)}
    print(name,json.dumps(out)); return out
res={}
res['all']=run('all',A.ITEMS)
res['cna']=run('cna',[i for i in A.ITEMS if src(i)=='cna'])
res['adp']=run('adp',[i for i in A.ITEMS if src(i).startswith('adp')])
json.dump(res,open('vector_source_check.json','w'),indent=1)
