#!/usr/bin/env python3
"""Bonus/penalty magnitude sweep for the hybrid.
Holds all other inputs at the Algorithm 5 defaults (balanced weight 3.0) and
varies the control-loss bonus and the weak-segmentation penalty independently.
Run from corpus_validation/:  python3 ../robustness_analyses/bonus_penalty_sweep.py
"""
import os, sys, json
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "corpus_validation"))
import analysis as A

def parts(it, cfg):
    c = {**A.DEF, **cfg}
    iv_score = A.score(it, {**cfg, 'bonus': True})  # populates nothing reusable; recompute below
    # rebuild calculator to read BC / CP / modifier
    from scoring.ivss_calculator import IVSSCalculator
    m = it['m']; meta = it['meta']; R = A.R
    iv = IVSSCalculator(); iv.set_cvss_calculator(it['calc']); iv.set_adjustment_method(c['method'])
    t = R.av_to_tiers(m.get('AV'))
    ex = 1.0 if it['kev'] else 0.5
    bc = R.derive_bc(m.get('C'), m.get('I'), m.get('A'))
    iv.set_base_metrics(rc=c['rc'], bc=bc, rl=c['rl'], ec=R.ac_at_to_ec(m), ex=ex,
                        au=R.pr_to_au(m.get('PR')), ui=R.ui_to_ivss(m.get('UI')), av=t['threat_vector'])
    iv.set_local_environment_metrics(la=t['asset_access'], cp=c['cp'])
    v = 1.0 if bc == 1.0 else 0.5 if bc == 0.75 else 0.0
    iv.set_process_consequence_metrics(vi=v, mi=v, ci=v)
    sectors = meta['sectors'] if meta else set(); sev = meta['severity'] if meta else ''
    iv.set_impact_metrics(pi=R.impact_tier(m.get('A')), ri=R.impact_tier(m.get('I')),
                          si=R.derive_si(sectors), cd=R.derive_cd(sev))
    raw = it['base'] + iv.calculate_modifier_impact() * 3.0
    ctrl = iv.metrics.get('BC') == iv.CONSEQUENCE_CONTROL
    weak = iv.metrics.get('CP') is not None and iv.metrics.get('CP') >= iv.NETWORK_SEGMENTATION_PARTIAL
    return raw, ctrl, weak, iv_score

def run(cp):
    P = [parts(it, {'cp': cp}) for it in A.ITEMS]
    raw = np.array([p[0] for p in P]); ctrl = np.array([p[1] for p in P]); weak = np.array([p[2] for p in P])
    ref = np.array([p[3] for p in P])
    return raw, ctrl, weak, ref

out = {}
for label, cp in [('default CP (penalty inactive)', 0.2), ('CP=none (penalty active)', 1.0)]:
    raw, ctrl, weak, ref = run(cp)
    chk = np.clip(raw + 0.5*ctrl + 0.6*weak, 0, 10)
    print(f"\n== {label}: control-tier CVEs {ctrl.mean()*100:.1f}%, penalty fires {weak.mean()*100:.1f}%, "
          f"max |recon-ref| {np.abs(chk-ref).max():.3f}")
    rows = []
    for b in [0.0, 0.25, 0.5, 0.8, 1.0, 1.5]:
        for p in ([0.6] if cp == 0.2 else [0.0, 0.3, 0.6, 0.9, 1.2]):
            s = np.clip(raw + b*ctrl + p*weak, 0, 10)
            d = A.summarize(f"b={b},p={p}", s)
            d = {k: (float(v) if isinstance(v, np.floating) else v) for k, v in d.items()}
            rows.append(d); print(d)
    out[label] = rows
json.dump(out, open('bonus_penalty_sweep.json', 'w'), indent=1)
