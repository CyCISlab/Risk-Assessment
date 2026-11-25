#!/usr/bin/env python3
"""
validate_fixed_values.py  -- do the assigned CP/LA fixed values hold up? (Section 5.2.4)

Connects the four assigned parameters (edge CP=0.20/LA=0.25, standard CP=0.85/LA=0.50)
to evidence, three ways:

  (1) CALIBRATION  -- assigned value vs the OBSERVED per-network inventory distribution.
                      Which assigned values match observation (suitable) and which sit
                      at the observed floor (biased)?
  (2) MONOTONICITY -- sweep CP: does a WORSE-segmented device ever score LOWER?
                      (a scheme bias independent of the chosen pair; what the
                       monotonic-penalty fix corrects.)
  (3) SENSITIVITY  -- architecture gap over the CP x LA grid: which axis dominates,
                      and where does the assigned point sit?

HOW TO RUN
  From this folder run:   python3 validate_fixed_values.py
  Requirements:  pip install 'cvss==3.6'
  Paths resolve relative to this file; override with env IVSS_PROJECT / IVSS_SUPPORT.
"""
import sys, os, json, statistics as st

def _first_existing(cands, what):
    for c in cands:
        if c and os.path.isdir(c):
            return c
    sys.exit(f"Could not locate {what}; tried:\n  " + "\n  ".join(filter(None, cands)))

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.dirname(_HERE)
PROJECT = _first_existing([os.environ.get("IVSS_PROJECT"),
                           os.path.join(_BASE, "Project Code"),
                           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Project Code")], "Project Code")
SUPPORT = _first_existing([os.environ.get("IVSS_SUPPORT"),
                           os.path.join(_BASE, "Support"),
                           os.path.join(_BASE, "simulation_results")], "Support")
sys.path.insert(0, PROJECT)

from scoring.ivss_calculator import IVSSCalculator as C
from scanning.device import Device
from scoring.device_modifiers import (calculate_network_segmentation_modifier as cp_fn,
                                       calculate_asset_access_modifier as la_fn)
NETS = {"standard": "standard_network", "edge": "edge_hidden_network"}
ASSIGNED = {"standard": (0.85, 0.50), "edge": (0.20, 0.25)}

def load(net):
    f = os.path.join(SUPPORT, NETS[net] + "_comprehensive_results.json")
    d = json.load(open(f))["devices"]; devs = []
    for ip, info in d.items():
        di = info.get("device_info", {})
        if not di:
            continue
        dev = Device(ip=ip, device_type=di.get("type", "U"), network=di.get("network", "U"),
                     hidden=di.get("hidden", False))
        det = info.get("detection_info", {})
        hidden = bool(di.get("hidden", False)); pcap = "pcap_hidden_device" in det
        dev.active_scan_status = "Detected" if not hidden else "Not Assessed"
        dev.passive_monitoring_status = "Detected" if (hidden and pcap) else "Not Assessed"
        dev.specialized_discovery_status = "Not Assessed"
        devs.append(dev)
    return devs
INV = {net: load(net) for net in NETS}

print(f"PROJECT = {PROJECT}\nSUPPORT = {SUPPORT}")

# ---------- (1) CALIBRATION ----------
print("\n" + "=" * 70)
print("(1) CALIBRATION   assigned value vs OBSERVED inventory distribution")
print("=" * 70)
for net in ("standard", "edge"):
    cps = [cp_fn(d) for d in INV[net]]; las = [la_fn(d) for d in INV[net]]
    acp, ala = ASSIGNED[net]
    def verdict(a, obs):
        lo, hi, m = min(obs), max(obs), st.mean(obs)
        return ("SUITABLE (~observed mean)" if abs(a - m) <= 0.1
                else ("at observed FLOOR/biased" if abs(a - lo) <= 0.01 else "in-range but off-mean")), lo, m, hi
    vC, loC, mC, hiC = verdict(acp, cps); vL, loL, mL, hiL = verdict(ala, las)
    print(f"\n  {net.upper()} (n={len(INV[net])})")
    print(f"    CP assigned={acp:.2f}  observed[min {loC:.2f}, mean {mC:.2f}, max {hiC:.2f}]  -> {vC}")
    print(f"    LA assigned={ala:.2f}  observed[min {loL:.2f}, mean {mL:.2f}, max {hiL:.2f}]  -> {vL}")

# ---------- (2) MONOTONICITY ----------
print("\n" + "=" * 70)
print("(2) MONOTONICITY   does a WORSE-segmented device ever score LOWER?")
print("=" * 70)
def score(cp, la):
    c = C(); c.set_adjustment_method("balanced")
    c.set_base_metrics(rc=1.0, bc=1.0, rl=0.0, ec=1.0, ex=1.0, au=1.0, ui=1.0, av=1.0)
    c.set_process_consequence_metrics(vi=1.0, mi=1.0, ci=1.0)
    try: c.set_impact_metrics(pi=1.0, ri=1.0, si=1.0)
    except Exception: pass
    c.set_local_environment_metrics(la=la, cp=cp)
    return c.calculate_final_score()
prev = None
for cp, name in [(0.20, "Compliant/best"), (0.75, "Partial"), (0.85, "DMZ-only"), (1.00, "None/WORST")]:
    s = score(cp, 0.5)
    flag = "  <-- NON-MONOTONIC (worse segmentation scores lower)" if (prev and s < prev) else ""
    print(f"    CP={cp:.2f} {name:15s} score={s:.3f}{flag}")
    prev = s

# ---------- (3) SENSITIVITY ----------
print("\n" + "=" * 70)
print("(3) SENSITIVITY   architecture gap over CP x LA grid (standard fixed at assigned)")
print("=" * 70)
std_ref = score(*ASSIGNED["standard"]); gla = [0.25, 0.50, 0.75, 1.00]; gcp = [0.20, 0.50, 0.75, 0.85]
print("        edge-LA: " + "  ".join(f"{la:>6.2f}" for la in gla))
for cp in gcp:
    print(f"  edge-CP {cp:.2f}: " + "  ".join(f"{std_ref - score(cp, la):>+6.2f}" for la in gla))
la_span = max(score(0.20, la) for la in gla) - min(score(0.20, la) for la in gla)
cp_span = max(score(cp, 0.25) for cp in gcp) - min(score(cp, 0.25) for cp in gcp)
print(f"\n  assigned edge (0.20,0.25) -> gap {std_ref - score(0.20, 0.25):+.3f}  (paper's +2.13)")
print(f"  score span from LA alone = {la_span:.3f}   from CP alone = {cp_span:.3f}"
      f"   -> gap ~{la_span / cp_span:.1f}x more sensitive to LA than CP")
