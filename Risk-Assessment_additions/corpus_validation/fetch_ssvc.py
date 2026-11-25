"""Download CISA Vulnrichment records for corpus CVEs and extract SSVC decision points -> ssvc.json."""
import json, os, concurrent.futures as cf, urllib.request
import analysis as A
os.makedirs('vr',exist_ok=True)
def get(cve):
    y,n=cve.split('-')[1:]; url=f"https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{y}/{int(n)//1000}xxx/{cve}.json"
    try: d=json.load(urllib.request.urlopen(url,timeout=30))
    except Exception: return cve,None
    for adp in d.get('containers',{}).get('adp',[]):
        for m in adp.get('metrics',[]):
            o=m.get('other',{})
            if o.get('type')=='ssvc':
                opts={}
                for x in o['content'].get('options',[]): opts.update(x)
                return cve,opts
    return cve,None
with cf.ThreadPoolExecutor(32) as ex: res=dict(ex.map(get,[i['cve'] for i in A.ITEMS]))
json.dump({k:v for k,v in res.items() if v},open('ssvc.json','w'))
