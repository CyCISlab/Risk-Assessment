#!/usr/bin/env python3
"""
coverage_by_sector_vendor.py  -- corpus coverage characterisation 

Computes usable-vector coverage (Section 5.4) by CISA critical-infrastructure
sector and by vendor. "Usable" = the CVE carries a published v3.x or v4.0 vector.
Reproduces the paper's overall figure (6,544 / 11,891 = 55.0%) and the per-sector
/ per-vendor breakdown reported in the Corpus-Coverage appendix.

HOW TO RUN
  python3 coverage_by_sector_vendor.py
  Needs, next to the project data:  cve_bulk_scores.csv  and
  ics_advisory_archive_merged_2010_2026.csv
  Override locations with env IVSS_BULK / IVSS_ARCHIVE.
"""
import os, sys, csv
from collections import defaultdict

def _find(cands, what):
    for c in cands:
        if c and os.path.isfile(c):
            return c
    sys.exit(f"Could not locate {what}; tried: " + ", ".join(filter(None, cands)))

_HERE = os.path.dirname(os.path.abspath(__file__))
_BASE = os.path.dirname(_HERE)
BULK = _find([os.environ.get("IVSS_BULK"),
             os.path.join(_BASE, "cve_bulk_scores.csv"),
             os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cve_bulk_scores.csv")], "cve_bulk_scores.csv")
ARCH = _find([os.environ.get("IVSS_ARCHIVE"),
             os.path.join(_BASE, "Project Code", "ics_advisory_archive_merged_2010_2026.csv"),
             os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ics_advisory_archive_merged_2010_2026.csv")], "advisory archive")

usable, vendor = {}, {}
with open(BULK) as f:
    for r in csv.DictReader(f):
        cve = r["CVE_Number"].strip()
        usable[cve] = bool(r["v3_vector"].strip()) or bool(r["v4_vector"].strip())
        vendor[cve] = (r.get("vendor") or "").strip()

tot, cov = len(usable), sum(usable.values())
print(f"overall: {cov}/{tot} = {100*cov/tot:.1f}% have a usable vector")

# ---- by sector (split compound 'A; B'; count each CVE once per sector) ----
sec = defaultdict(lambda: [set(), set()])
with open(ARCH) as f:
    for r in csv.DictReader(f):
        cve = (r.get("CVE_Number") or "").strip()
        if not cve or cve not in usable:
            continue
        raw = (r.get("Critical_Infrastructure_Sector") or "").strip() or "Unspecified"
        for s in (x.strip() for x in raw.split(";") if x.strip()):
            sec[s][0].add(cve)
            if usable[cve]:
                sec[s][1].add(cve)
print("\nCoverage by sector:")
for s, (cves, uc) in sorted(sec.items(), key=lambda x: -len(x[1][0]))[:10]:
    print(f"  {s[:34]:34} n={len(cves):5} coverage={100*len(uc)/len(cves):4.0f}%")

# ---- by vendor (merge obvious variants; drop n/a) ----
def norm(v):
    low = v.strip().lower()
    if low in ("n/a", "", "unknown"):
        return None
    for pre, name in (("siemens", "Siemens"), ("schneider", "Schneider Electric"),
                      ("rockwell", "Rockwell Automation"), ("mitsubishi", "Mitsubishi Electric")):
        if low.startswith(pre):
            return name
    return v.strip()

vc = defaultdict(lambda: [0, 0])
for cve, u in usable.items():
    v = norm(vendor[cve])
    if v is None:
        continue
    vc[v][0] += 1
    vc[v][1] += int(u)
print("\nCoverage by vendor (merged variants, n/a excluded):")
for v, (n, c) in sorted(vc.items(), key=lambda x: -x[1][0])[:8]:
    print(f"  {v[:26]:26} n={n:5} coverage={100*c/n:4.0f}%")
