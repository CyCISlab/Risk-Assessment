#!/usr/bin/env python3
"""
faithful_arch_factorial.py  -- RQ2 architecture-effect ablation (Section 5.2.4)

WHAT IT DOES
  Reproduces the submitted scoring path EXACTLY (all network devices injected into
  each scenario; assess_vulnerability() scores the first affected device), then
  toggles the CP (segmentation) and LA (asset-access) sources independently:
        CP in {assigned, device} x LA in {assigned, device, fixed}
  to show the architecture gap is a property of the ASSIGNED per-network values,
  not of observation.

SANITY CHECKS (must hold, printed below)
  * assigned/assigned standalone gap == +2.1278 for every vulnerability
  * assigned/assigned hybrid gap: SCADA DoS +1.7125, Modbus RCE 0.0
    (matches Support/network_comparison_score_differences.json)

KEY RESULT
  * CP=device, LA=device  ->  standalone gap +0.000   (the +2.13 collapses)
  * decomposition: 2.128 raw = 0.600 (CP assignment) + 1.528 (LA assignment)

HOW TO RUN
  From this folder run:   python3 faithful_arch_factorial.py
  Requirements:  pip install 'cvss==3.6'   (the Project Code calculators need it)
  Paths are resolved relative to this file; override with env IVSS_PROJECT / IVSS_SUPPORT.
"""
import sys, os, json, statistics as st, logging
logging.disable(logging.CRITICAL)

# ---- robust path resolution (Mac: ../Project Code, ../Support ; container fallback) ----
def _first_existing(cands, what):
    for c in cands:
        if c and os.path.isdir(c):
            return c
    sys.exit(f"Could not locate {what}; tried:\n  " + "\n  ".join(filter(None, cands)))

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.dirname(_HERE)  # 'Code and Data'
PROJECT = _first_existing([os.environ.get("IVSS_PROJECT"),
                           os.path.join(_BASE, "Project Code"),
                           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Project Code")], "Project Code")
SUPPORT = _first_existing([os.environ.get("IVSS_SUPPORT"),
                           os.path.join(_BASE, "Support"),
                           os.path.join(_BASE, "simulation_results")], "Support")
sys.path.insert(0, PROJECT)

from scanning.device import Device
from scoring.ivss_calculator import IVSSCalculator as C
from scoring.device_modifiers import (calculate_network_segmentation_modifier as cp_fn,
                                       calculate_asset_access_modifier as la_fn)
from scenarios.modbus_vulnerability import ModbusTCPRCEVulnerability
from scenarios.scada_dos_vulnerability import SCADADenialOfServiceVulnerability
from scenarios.firmware_update_vulnerability import FirmwareUpdateVulnerability

ASSIGNED = {"standard": (C.NETWORK_SEGMENTATION_DMZ_ONLY,  C.ASSET_ACCESS_LOCAL_NETWORK),   # 0.85, 0.50
            "edge":     (C.NETWORK_SEGMENTATION_COMPLIANT, C.ASSET_ACCESS_LOCAL_HOST)}        # 0.20, 0.25
FIXED_LA = 0.5
NETS = {"standard": "standard_network", "edge": "edge_hidden_network"}
COMMON = [("SCADA DoS", SCADADenialOfServiceVulnerability),
          ("Modbus RCE", ModbusTCPRCEVulnerability),
          ("Firmware Bypass", FirmwareUpdateVulnerability)]  # Firmware hybrid n/a: pre-existing CVSS4 'SC:M' bug

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

def run(cls, net, cp_mode, la_mode):
    os.environ["SIMULATION_TYPE"] = NETS[net]
    s = cls()
    for d in INV[net]:
        s.add_device(d)
    acp, ala = ASSIGNED[net]
    def patched(network_type, _s=s, _acp=acp, _ala=ala):
        fd = next(iter(_s.affected_devices)) if getattr(_s, "affected_devices", None) else None
        cp = cp_fn(fd) if (cp_mode == "device" and fd) else _acp
        if la_mode == "device" and fd:   la = la_fn(fd)
        elif la_mode == "fixed":          la = FIXED_LA
        else:                             la = _ala
        return cp, la
    s._get_network_configuration = patched
    s.assess_vulnerability()
    return getattr(s, "standalone_ivss_score", None), getattr(s, "hybrid_ivss_score", None)

def gaps(cp_mode, la_mode):
    out = []
    for vname, cls in COMMON:
        try:
            ss, hs = run(cls, "standard", cp_mode, la_mode)
            se, he = run(cls, "edge", cp_mode, la_mode)
            out.append((vname, (ss - se) if None not in (ss, se) else None,
                        (hs - he) if None not in (hs, he) else None))
        except Exception:
            out.append((vname, None, None))
    return out

print(f"PROJECT = {PROJECT}\nSUPPORT = {SUPPORT}\n")
print("CP x LA factorial  (architecture gap = standard - edge)")
print("expect: assigned/assigned std +2.1278 all; hybrid SCADA +1.7125, Modbus 0.0\n")
for cp_mode in ("assigned", "device"):
    for la_mode in ("assigned", "device", "fixed"):
        rows = gaps(cp_mode, la_mode)
        sv = [r[1] for r in rows if r[1] is not None]
        hv = [r[2] for r in rows if r[2] is not None]
        f = lambda x: f"{x:+.3f}" if x is not None else "  n/a"
        print(f"[CP={cp_mode:8s} LA={la_mode:8s}]  mean std-gap={st.mean(sv):+.4f}"
              + (f"  mean net-gap={st.mean(hv):+.4f}" if hv else "  net=n/a"))
        print("      " + "   ".join(f"{n}: std{f(sg)}/net{f(hg)}" for n, sg, hg in rows))
print("\nReading: CP=device/LA=device collapses the +2.13 raw gap to ~0;")
print("2.128 = 0.600 (CP assignment) + 1.528 (LA assignment).")
