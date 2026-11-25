import numpy as np, json
import analysis as A
from scoring.ivss_calculator import IVSSCalculator
from sklearn.metrics import roc_auc_score
z=np.load('scores.npz'); kev=z['kev']; ss=json.load(open('ssvc.json'))
m=np.array([i['cve'] in ss for i in A.ITEMS]); ti=np.array([ss[i['cve']]['Technical Impact']=='total' for i in A.ITEMS if i['cve'] in ss]).astype(int)
orig=IVSSCalculator.calculate_final_score
def spec(self):
    bs=self.calculate_base_severity_score(); ai=self.calculate_adjusted_criticality(); aa=self.calculate_adjusted_accessibility()
    s=(bs+ai*5+aa*10)/16; s=max(0,min(10,s)); self.scores['FINAL']=s; return s
for lab,f in [('paper (6/11/18 + bonus/penalty)',orig),('IVSS spec (5/10/16, no bonus)',spec)]:
    IVSSCalculator.calculate_final_score=f
    s=np.array([A.score(i,{'mode':'standalone','ex_kev':False}) for i in A.ITEMS]); d=A.summarize(lab,s)
    print(f"{lab:34s} r={float(d['r']):.3f} esc={float(d['escalate']):.1f} de={float(d['deescalate']):.1f} clip={float(d['clip10']):.1f} KEV={roc_auc_score(kev,s):.3f} TI={roc_auc_score(ti,s[m]):.3f}")
IVSSCalculator.calculate_final_score=orig
