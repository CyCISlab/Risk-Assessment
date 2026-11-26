#!/usr/bin/env python3
"""RQ2 check: does a hidden device score lower because of where it is,
or because asset access (LA) is derived from how it was detected?
Scores every simulated device with LA from its detection outcome (as in the framework)
and with LA from its network zone alone (oracle reachability), then compares hidden and
visible devices in the same zone. Run from robustness_analyses/."""
import sys, json, statistics as st
sys.path.insert(0, '../Project Code')
from scoring.ivss_calculator import IVSSCalculator as C
from scanning.device import Device
from scoring.device_modifiers import (calculate_network_segmentation_modifier as cp_fn,
                                      calculate_asset_access_modifier as la_fn)
def score(cp, la):
    c = C(); c.set_adjustment_method('balanced')
    c.set_base_metrics(rc=1.0, bc=1.0, rl=0.0, ec=1.0, ex=1.0, au=1.0, ui=1.0, av=1.0)
    c.set_process_consequence_metrics(vi=1.0, mi=1.0, ci=1.0)
    try: c.set_impact_metrics(pi=1.0, ri=1.0, si=1.0)
    except Exception: pass
    c.set_local_environment_metrics(la=la, cp=cp); return c.calculate_final_score()
ZONE_LA = {'IT': 1.0, 'DMZ': 1.0, 'MAINTENANCE': 1.0, 'CONTROL': 0.5, 'PROCESS': 0.5}
for net in ['standard_network', 'edge_hidden_network']:
    dv = json.load(open(f'../simulation_results/{net}_comprehensive_results.json'))['devices']
    rows = []
    for ip, info in dv.items():
        di = info.get('device_info', {})
        if not di: continue
        d = Device(ip=ip, device_type=di.get('type'), network=di.get('network'), hidden=di.get('hidden', False))
        h = bool(di.get('hidden')); found = 'pcap_hidden_device' in info.get('detection_info', {})
        d.active_scan_status = 'Detected' if not h else 'Not Assessed'
        d.passive_monitoring_status = 'Detected' if (h and found) else 'Not Assessed'
        d.specialized_discovery_status = 'Not Assessed'
        zone = [k for k in ZONE_LA if k in di.get('network', '').upper()][0]
        rows.append(dict(type=di['type'], zone=zone, hidden=h, found=found,
                         det=score(cp_fn(d), la_fn(d)), reach=score(cp_fn(d), ZONE_LA[zone])))
    for z in ['PROCESS']:
        V = [r for r in rows if not r['hidden'] and r['zone'] == z]
        F = [r for r in rows if r['hidden'] and r['found'] and r['zone'] == z]
        print(net, z, 'visible det %.2f reach %.2f | hidden-found det %.2f reach %.2f' % (
            st.mean(r['det'] for r in V), st.mean(r['reach'] for r in V),
            st.mean(r['det'] for r in F), st.mean(r['reach'] for r in F)))
