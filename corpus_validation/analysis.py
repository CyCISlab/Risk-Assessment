import csv, os, sys, json, math
import numpy as np
_here=os.path.dirname(os.path.abspath(__file__))
for _p in [os.path.join(_here,"Project Code"), os.path.join(_here,"..","Project Code"), os.path.join(_here,"..","..","Project Code"), os.path.join(_here,"..")]:
    if os.path.isdir(_p): sys.path.insert(0,_p)
sys.path.insert(0, os.path.join(_here, "..", "robustness_analyses"))
DATA = os.environ.get("IVSS_DATA", os.path.join(_here, ".."))
import rbs_param as R
from scoring.cvss3_calculator import CVSSv3Calculator
from scoring.cvss_calculator import CVSSv4Calculator
from scoring.ivss_calculator import IVSSCalculator

def band(s): return 3 if s>=9 else 2 if s>=7 else 1 if s>=4 else 0

KEV=R.load_kev_ids(os.path.join(DATA,'known_exploited_vulnerabilities.json'))
META=R.load_advisory_metadata(os.path.join(DATA,'ics_advisory_archive_merged_2010_2026.csv'))
rows=list(csv.DictReader(open(os.path.join(DATA,'cve_scores_extracted.csv'),encoding='utf-8',errors='replace')))

def worse(a,b):
    o={"H":2,"L":1,"N":0,None:0}; return a if o.get(a,0)>=o.get(b,0) else b

# Pre-parse base calcs once
ITEMS=[]
for r in rows:
    cve=r['CVE_Number']; c=None; m=None; basis=None
    v4=r.get('v4_vector','').strip(); v3=r.get('v3_vector','').strip()
    if v4:
        try:
            c=CVSSv4Calculator.from_vector_string(v4); c.calculate_base_score()
            mm=R.parse_vector_metrics(v4); m=dict(mm)
            m['C']=worse(mm.get('VC'),mm.get('SC')); m['I']=worse(mm.get('VI'),mm.get('SI')); m['A']=worse(mm.get('VA'),mm.get('SA')); basis='v4.0'
        except Exception: c=None
    if c is None and v3:
        try:
            c=CVSSv3Calculator.from_vector_string(v3); c.calculate_base_score(); m=R.parse_vector_metrics(v3); basis='v3.1'
        except Exception: c=None
    if c is None: continue
    ITEMS.append(dict(cve=cve,calc=c,m=m,basis=basis,base=float(c.calculate_base_score()),kev=cve in KEV,meta=META.get(cve),v3=v3,v4=v4))
print('usable',len(ITEMS),'kev',sum(i['kev'] for i in ITEMS))

DEF=dict(mode='hybrid',method='balanced',cp=0.2,rl=0.0,rc=1.0,ex_kev=True,si='sector',cd='severity',bc='triad',vmc='bc',la='mirror',bonus=True)
def score(it,cfg):
    c={**DEF,**cfg}; m=it['m']; meta=it['meta']
    iv=IVSSCalculator()
    if c['mode']=='hybrid': iv.set_cvss_calculator(it['calc'])
    iv.set_adjustment_method(c['method'])
    t=R.av_to_tiers(m.get('AV'))
    ex=(1.0 if it['kev'] else 0.5) if c['ex_kev'] else 0.5
    bc=R.derive_bc(m.get('C'),m.get('I'),m.get('A')) if c['bc']=='triad' else {'cwe_none':0.5}.get(c['bc'],0.5)
    if c['bc']=='availability_only':  # alt mapping: control only from A:H, ignore I
        bc=0.75 if m.get('A')=='H' else (0.5 if m.get('I') in ('H','L') else 0.25)
    iv.set_base_metrics(rc=c['rc'],bc=bc,rl=c['rl'],ec=R.ac_at_to_ec(m),ex=ex,au=R.pr_to_au(m.get('PR')),ui=R.ui_to_ivss(m.get('UI')),av=t['threat_vector'])
    la=t['asset_access'] if c['la']=='mirror' else c['la']
    iv.set_local_environment_metrics(la=la,cp=c['cp'])
    if c['vmc']=='bc':
        v=1.0 if bc==1.0 else 0.5 if bc==0.75 else 0.0
        vi=mi=ci=v
    elif c['vmc']=='split':  # visibility<-C, monitoring<-I, control<-I&A
        L={'H':1.0,'L':0.5,'N':0.0}
        vi=L.get(m.get('C'),0); mi=L.get(m.get('I'),0); ci=1.0 if (m.get('I')=='H' and m.get('A')=='H') else 0.5 if m.get('A')=='H' else 0.0
    else: vi=mi=ci=float(c['vmc'])
    iv.set_process_consequence_metrics(vi=vi,mi=mi,ci=ci)
    sectors=meta['sectors'] if meta else set(); sev=meta['severity'] if meta else ''
    si=R.derive_si(sectors) if c['si']=='sector' else float(c['si'])
    cd=R.derive_cd(sev) if c['cd']=='severity' else float(c['cd'])
    iv.set_impact_metrics(pi=R.impact_tier(m.get('A')),ri=R.impact_tier(m.get('I')),si=si,cd=cd)
    if not c['bonus']:
        # remove bonus/penalty by scoring then subtracting
        s=iv.calculate_final_score()
        add=0.0
        if iv.metrics.get('BC')==iv.CONSEQUENCE_CONTROL: add+= 0.8 if c['method']=='aggressive' else 0.5
        if iv.metrics.get('CP') is not None and iv.metrics.get('CP')>=iv.NETWORK_SEGMENTATION_PARTIAL: add+= 0.9 if c['method']=='aggressive' else 0.6
        # recompute unclipped
        if c['mode']=='hybrid':
            w={'aggressive':4.0,'conservative':1.5}.get(c['method'],3.0)
            raw=it['base']+iv.calculate_modifier_impact()*w
        else:
            bs=iv.calculate_base_severity_score(); ai=iv.calculate_adjusted_criticality(); aa=iv.calculate_adjusted_accessibility()
            raw=(bs+ai*6+aa*11)/18
        return max(0.0,min(10.0,raw))
    return iv.calculate_final_score()

def summarize(name,s):
    b=np.array([it['base'] for it in ITEMS]); s=np.array(s)
    bb=np.array([band(x) for x in b]); sb=np.array([band(round(x,1)) for x in s])
    esc=(sb>bb).mean()*100; de=(sb<bb).mean()*100; disc=(sb!=bb).sum()
    r=np.corrcoef(b,s)[0,1]
    clip=(np.round(s,1)>=10.0).mean()*100
    return dict(cfg=name,n=len(s),r=round(r,3),mean_delta=round((s-b).mean(),2),escalate=round(esc,1),deescalate=round(de,1),disagree=round(esc+de,1),esc_share_of_disc=round(100*(sb>bb).sum()/disc,1) if disc else None,clip10=round(clip,1))
