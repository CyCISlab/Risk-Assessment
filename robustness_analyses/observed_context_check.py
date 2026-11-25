#!/usr/bin/env python3
"""Observed-context spot-check .
Replaces the corpus's fixed segmentation (CP) and mirrored asset access (LA) with values
derived per device from the simulated inventories (same derivation as Section 5.2.4).
Each CVE is matched by product/advisory keywords to a device class; its hybrid score is
the mean over every simulated device of that class in both networks. CVEs whose class
cannot be identified are excluded. Escalation, KEV and SSVC results are compared with the
fixed-default hybrid and CVSS base on the same CVEs.
Run from corpus_validation/ after run_all.py and fetch_ssvc.py:
    python3 ../robustness_analyses/observed_context_check.py
"""
import os, sys, csv, re, json
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(BASE, "corpus_validation"))
import analysis as A
from scanning.device import Device
from scoring.device_modifiers import (calculate_network_segmentation_modifier as cp_fn,
                                      calculate_asset_access_modifier as la_fn)

# --- per-device observed context from the simulated inventories (as in validate_fixed_values.py)
SIM = os.path.join(BASE, "simulation_results")
CLASS_OF = [  # simulated device type -> class
    (r"PLC", "controller"), (r"HMI|SCADA|Maintenance Server|IT Management", "supervisory"),
    (r"EWS|Engineering", "engineering"),
    (r"Router|Gateway|Converter|Firewall|Vendor Connection|Maintenance Interface", "network"),
    (r"Sensor|Serial Device|Backup", "field")]
def dclass(t):
    for p, c in CLASS_OF:
        if re.search(p, t or ""): return c
    return None
DEV = {}
for net in ["standard_network", "edge_hidden_network"]:
    for ip, info in json.load(open(os.path.join(SIM, f"{net}_comprehensive_results.json")))["devices"].items():
        di = info.get("device_info", {})
        if not di: continue
        d = Device(ip=ip, device_type=di.get("type", "U"), network=di.get("network", "U"), hidden=di.get("hidden", False))
        hidden = bool(di.get("hidden", False)); pcap = "pcap_hidden_device" in info.get("detection_info", {})
        d.active_scan_status = "Detected" if not hidden else "Not Assessed"
        d.passive_monitoring_status = "Detected" if (hidden and pcap) else "Not Assessed"
        d.specialized_discovery_status = "Not Assessed"
        c = dclass(di.get("type"))
        if c: DEV.setdefault(c, []).append((net, di.get("type"), round(cp_fn(d), 3), round(la_fn(d), 3)))

# --- CVE -> device class from advisory product/title text
KW = [("controller", r"\bPLCs?\b|controller|\bRTUs?\b|\bDCS\b|SIMATIC S7|Modicon|ControlLogix|CompactLogix|MicroLogix|MELSEC|\bIEDs?\b|\bPAC\b"),
      ("engineering", r"engineering|programming|\bstudio\b|TIA Portal|STEP ?7|configurator|\bIDE\b|workbench"),
      ("supervisory", r"\bHMI\b|SCADA|historian|WinCC|InTouch|iFIX|CIMPLICITY|Citect|\bOPC\b|server|web ?panel|operator"),
      ("network", r"gateway|router|switch|firewall|converter|\bNPort\b|serial device server|\bVPN\b|modem|access point|wireless"),
      ("field", r"sensor|meter|transmitter|relay|drive|\bI/O\b|actuator|inverter|analy[sz]er|camera")]
title = {}
for r in csv.DictReader(open(os.path.join(A.DATA, "ics_advisory_archive_merged_2010_2026.csv"), encoding="utf-8", errors="replace")):
    txt = " ".join([r.get("ICS-CERT_Advisory_Title") or "", r.get("Product") or "", r.get("Products_Affected") or ""])
    for c in (r.get("CVE_Number") or "").split(","):
        c = c.strip()
        if c.startswith("CVE-"): title[c] = title.get(c, "") + " " + txt
def cclass(cve):
    t = title.get(cve, "")
    for c, p in KW:
        if re.search(p, t, re.I): return c
    return None

idx, cls = [], []
for k, it in enumerate(A.ITEMS):
    c = cclass(it["cve"])
    if c and c in DEV: idx.append(k); cls.append(c)
I = [A.ITEMS[k] for k in idx]
base = np.array([i["base"] for i in I]); kev = np.array([i["kev"] for i in I]).astype(int)
fixed = np.array([A.score(i, {}) for i in I])
obs = np.array([np.mean([A.score(i, {"cp": cp, "la": la}) for (_, _, cp, la) in DEV[c]]) for i, c in zip(I, cls)])

def esc(s):
    bb = np.array([A.band(x) for x in base]); sb = np.array([A.band(round(x, 1)) for x in s])
    e, d = (sb > bb).mean() * 100, (sb < bb).mean() * 100
    return round(e, 1), round(d, 1), round(100 * (sb > bb).sum() / max(1, (sb != bb).sum()), 1)
out = {"n_matched": len(I), "n_corpus": len(A.ITEMS), "n_kev": int(kev.sum()),
       "class_counts": {c: cls.count(c) for c in sorted(set(cls))},
       "devices": {c: [list(x) for x in v] for c, v in DEV.items()}}
for name, s in [("CVSS base", base), ("hybrid fixed defaults", fixed), ("hybrid observed context", obs)]:
    out[name] = {"escalate_deesc_share": esc(s) if name != "CVSS base" else None,
                 "r_vs_CVSS": round(float(np.corrcoef(base, s)[0, 1]), 3), "KEV_AUC": round(roc_auc_score(kev, s), 3)}
rng = np.random.default_rng(0)
P, N = np.where(kev == 1)[0], np.where(kev == 0)[0]; dd = []
for _ in range(2000):
    j = np.r_[rng.choice(P, len(P)), rng.choice(N, len(N))]; dd.append(roc_auc_score(kev[j], obs[j]) - roc_auc_score(kev[j], base[j]))
out["hybrid observed context"]["KEV_diff_vs_CVSS_CI"] = [round(x, 3) for x in np.percentile(dd, [2.5, 97.5])]
ssp = os.path.join(BASE, "corpus_validation", "ssvc.json")
if os.path.exists(ssp):
    ss = json.load(open(ssp)); m = np.array([i["cve"] in ss for i in I])
    ti = np.array([ss[i["cve"]]["Technical Impact"] == "total" for i in I if i["cve"] in ss]).astype(int)
    for name, s in [("CVSS base", base), ("hybrid fixed defaults", fixed), ("hybrid observed context", obs)]:
        out[name]["SSVC_TI_AUC"] = round(roc_auc_score(ti, s[m]), 3)
    keys = ['AV', 'AC', 'PR', 'UI', 'C', 'I', 'A']
    X = np.array([[1.0 if i['m'].get(k) == v else 0.0 for k in keys for v in ['N', 'A', 'L', 'P', 'H', 'R']] for i in I])[m]
    pv = cross_val_predict(LogisticRegression(max_iter=2000), X, ti, cv=10, method='predict_proba')[:, 1]
    ph = cross_val_predict(LogisticRegression(max_iter=2000), np.c_[X, obs[m]], ti, cv=10, method='predict_proba')[:, 1]
    out["SSVC vector-only AUC"] = round(roc_auc_score(ti, pv), 3); out["SSVC vector+observed-hybrid AUC"] = round(roc_auc_score(ti, ph), 3)
    out["n_ssvc"] = int(m.sum())
print(json.dumps({k: v for k, v in out.items() if k != "devices"}, indent=1))
print("devices:", json.dumps(out["devices"]))
json.dump(out, open("observed_context_check.json", "w"), indent=1)
