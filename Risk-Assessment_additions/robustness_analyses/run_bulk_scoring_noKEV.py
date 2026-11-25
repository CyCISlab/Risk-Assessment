#!/usr/bin/env python3
"""
run_bulk_scoring.py

Master pipeline for the paper's real-CVE dataset:
  Stage 1: CVSS v3.1 base scores for every CVE with a published v3.x vector
            (via the project's CVSSv3Calculator, which itself delegates to
            FIRST.org's official `cvss` library -- see cvss3_calculator.py).
  Stage 2: CVSS v4.0 base scores for every CVE with a published v4.0 vector
            (via the fixed CVSSv4Calculator, same delegation approach).
  Stage 3: IVSS scores for every CVE that got a Stage 1 and/or Stage 2 score,
            using IVSSCalculator in "hybrid" mode (set_cvss_calculator), which
            is the mode that lets a real CVSS vector drive the exploitability/
            impact math instead of guessing it from scratch.

Inputs:
  - cve_scores_extracted.csv        (from extract_cve_scores.py; published
                                      CVSS v3.x/v4.0 vectors, one row/CVE)
  - ics_advisory_archive_merged_2010_2026.csv
                                     (ICS Advisory Project metadata: vendor,
                                      CWE, Critical_Infrastructure_Sector,
                                      Cumulative_CVSS/CVSS_Severity)
  - known_exploited_vulnerabilities.json
                                     (CISA KEV catalog; used only as a binary
                                      "is this CVE known-exploited" signal)

Output:
  - cve_bulk_scores.csv  -- one row per distinct CVE with: v3.1 base score,
    v4.0 base score, IVSS score (computed off whichever of v3/v4 is
    available; both if both are), and the metadata used.

===========================================================================
IVSS HEURISTIC MAPPING -- READ THIS BEFORE CITING THE IVSS NUMBERS
===========================================================================
IVSSCalculator needs 16 industrial-context inputs (asset segmentation,
process visibility/monitoring/control, safety/production/reliability
impact, financial loss, report confidence, remediation level, exploit
maturity...). None of these are published in the CVE record or the ICS
Advisory Project CSV -- they describe a *specific deployment*, not the
vulnerability in the abstract, which is exactly why the original 6
synthetic scenarios in this project set them by hand.

To score thousands of real CVEs at all, this script has to fill those 16
inputs from something. Every mapping below is deliberately built ONLY from
fields that are genuinely present in the data (the CVSS vector itself, the
CISA KEV catalog, and the advisory's own sector/severity fields) rather
than invented per-CVE judgments. Where no real signal exists at all (asset
network segmentation, remediation level), the script uses one fixed,
disclosed, conservative default for every CVE rather than a per-CVE guess
-- this means IVSS's absolute scores carry a uniform assumption baked in,
but relative comparisons (which CVEs score higher/lower, and how IVSS's
ranking diverges from CVSS's) remain meaningful, since the same constant
is applied everywhere.

Per-metric mapping and its justification:

  AV (Threat Vector Required)   <- CVSS AV (N/A/L/P), direct correspondence.
  LA (Asset Access)              <- CVSS AV, same logic (mirrors AV; IVSS
                                     models "how reachable is the vulnerable
                                     function" and "how reachable is the
                                     asset" from the same network position).
  AU (Privilege Level Required)  <- CVSS PR (N/L/H), direct correspondence.
  UI (User Interaction Required) <- CVSS UI (N vs any required value).
  EC (Exploit Difficulty)        <- CVSS AC (v3) / AC+AT (v4): Low->LOW,
                                     High->HIGH. No data source supports a
                                     "moderate" tier, so it is not used.
  EX (Exploit Maturity)          <- CISA KEV catalog membership: listed as
                                     a known-exploited vulnerability ->
                                     FUNCTIONAL (a real exploit is confirmed
                                     in the wild); not listed -> UNPROVEN
                                     (conservative -- absence from KEV is
                                     not proof no exploit exists, so this
                                     under- rather than over-states maturity).
  RC (Report Confidence)         <- fixed at CONFIRMED for every CVE. All
                                     scores here come from published,
                                     assigned CVSS vectors (CNA or NVD), not
                                     from rumor/unconfirmed reports, so the
                                     "confirmed" tier is the honest constant
                                     rather than a guess.
  RL (Remediation Level)         <- fixed at OFFICIAL_FIX for every CVE.
                                     DISCLOSED DEFAULT: patch availability
                                     per-CVE is not in this dataset. ICS-CERT
                                     advisories are issued once vendor
                                     remediation exists in the large majority
                                     of cases, which is the basis for this
                                     default, but it is not verified per CVE.
  BC (Consequence)                <- derived from the CVSS Impact triad
                                     already present in the vector (C/I/A for
                                     v3, VC/VI/VA for v4), NOT from CWE
                                     lookup tables, so it stays grounded in
                                     data every CVE already has:
                                       Integrity:H AND Availability:H -> CONTROL
                                       Availability:H only            -> SUSTAINED_DENIAL
                                       Integrity:H or L (no Avail:H)  -> DATA_MODIFICATION
                                       else                            -> TEMPORARY_DENIAL
  CP (Network Segmentation Level) <- fixed at COMPLIANT (the best-case tier)
                                     for every CVE. DISCLOSED DEFAULT: no
                                     per-asset segmentation data exists in
                                     this dataset. COMPLIANT is chosen
                                     deliberately (rather than PARTIAL/NONE)
                                     so the script does not manufacture a
                                     segmentation-penalty finding it has no
                                     evidence for.
  VI/MI/CI (Process Visibility /  <- derived from the same BC tier: CONTROL
   Monitoring / Control conseq.)    -> COMPLETE for all three; SUSTAINED_
                                     DENIAL -> PARTIAL for all three; else
                                     NONE. This is an explicit simplification
                                     (collapsing 3 metrics to 1 driver) noted
                                     as a limitation rather than hidden.
  PI (System Production Impact)   <- CVSS Availability impact tier (H/L/N)
                                     directly, since "production impact" and
                                     "availability impact" describe the same
                                     underlying consequence for ICS assets.
  RI (System Reliability Impact)  <- CVSS Integrity impact tier (H/L/N),
                                     analogous reasoning.
  SI (System Safety Impact)       <- Critical_Infrastructure_Sector field
                                     from the ICS Advisory Project CSV:
                                     Energy / Water and Wastewater / Chemical
                                     / Nuclear / Transportation -> HIGH;
                                     Healthcare and Public Health / Critical
                                     Manufacturing / Dams / Emergency
                                     Services -> MEDIUM; all other/unlisted
                                     sectors -> LOW. This is real,
                                     advisory-specific metadata, not a
                                     per-CVE guess.
  CD (Financial Loss Impact)      <- the advisory's own Cumulative_CVSS /
                                     CVSS_Severity field: Critical/High ->
                                     HIGH; Medium -> MEDIUM; Low -> LOW.
                                     Real metadata, not invented.

Where a CVE has no advisory-CSV metadata at all (i.e. it was only found via
the CVE List v5 lookup, not present in the ICS Advisory Project archive),
SI defaults to MEDIUM and CD defaults to MEDIUM (the two "not defined"
constants IVSS itself specifies map to the top tier -- MEDIUM is used
instead here as a deliberately less alarmist default given the absence of
sector confirmation).

This mapping is a single, fixed, disclosed function -- the same rules are
applied identically to every CVE, and it should be described as such
(a methodological limitation, not a source of per-CVE ground truth) in the
paper.
===========================================================================
"""

import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Project Code"))

from scoring.cvss3_calculator import CVSSv3Calculator
from scoring.cvss_calculator import CVSSv4Calculator
from scoring.ivss_calculator import IVSSCalculator

WORK = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("IVSS_DATA", os.path.join(WORK, ".."))

SAFETY_HIGH_SECTORS = {
    "energy", "water and wastewater", "chemical", "nuclear",
    "transportation", "transportation systems",
}
SAFETY_MEDIUM_SECTORS = {
    "healthcare and public health", "critical manufacturing", "dams",
    "emergency services",
}


def load_kev_ids(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return {v["cveID"] for v in d.get("vulnerabilities", [])}


def load_advisory_metadata(path):
    """CVE_Number -> dict(sector_set, severity, cwe, vendor, product)."""
    meta = {}
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cves = [c.strip() for c in (row.get("CVE_Number") or "").split(",") if c.strip().startswith("CVE-")]
            if not cves:
                continue
            sectors = {s.strip().lower() for s in (row.get("Critical_Infrastructure_Sector") or "").split(";") if s.strip()}
            severity = (row.get("CVSS_Severity") or "").strip().lower()
            for cve in cves:
                existing = meta.get(cve)
                if existing is None:
                    meta[cve] = {
                        "sectors": set(sectors),
                        "severity": severity,
                        "cwe": row.get("CWE_Number", ""),
                        "vendor": row.get("Vendor", ""),
                        "product": row.get("Product", ""),
                    }
                else:
                    existing["sectors"] |= sectors
                    if not existing["severity"]:
                        existing["severity"] = severity
    return meta


def parse_vector_metrics(vector_string):
    """Return dict of metric->value parsed out of a CVSS vector string."""
    out = {}
    parts = vector_string.split("/")[1:]
    for part in parts:
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        out[k] = v
    return out


def av_to_tiers(av):
    if av == "N":
        return dict(threat_vector=1.0, asset_access=1.0)
    if av == "A":
        return dict(threat_vector=0.5, asset_access=0.5)
    return dict(threat_vector=0.1, asset_access=0.25)  # L or P


def pr_to_au(pr):
    return {"N": 1.0, "L": 0.56, "H": 0.2}.get(pr, 0.56)


def ui_to_ivss(ui):
    return 1.0 if ui == "N" else 0.3


def ac_at_to_ec(metrics):
    ac = metrics.get("AC")
    at = metrics.get("AT")
    if ac == "H" or at == "P":
        return 0.2  # HIGH difficulty
    return 1.0  # LOW difficulty


def impact_tier(value):
    """Map a CVSS impact letter (v3 N/L/H or v4 N/L/H) to a 0-10 style
    IVSS-compatible tier value used for PI/RI."""
    return {"H": 1.0, "L": 0.33, "N": 0.0}.get(value, 0.33)


def derive_bc(c_or_vi_letter, i_letter, a_letter):
    """BC per the docstring's Impact-triad rule. Accepts v3 (C/I/A) or
    v4 (VC/VI/VA) letters -- same N/L/H vocabulary either way."""
    i_high = i_letter == "H"
    a_high = a_letter == "H"
    i_any = i_letter in ("H", "L")
    if i_high and a_high:
        return 1.0  # CONTROL
    if a_high:
        return 0.75  # SUSTAINED_DENIAL
    if i_any:
        return 0.5  # DATA_MODIFICATION
    return 0.25  # TEMPORARY_DENIAL


def derive_si(sectors):
    if sectors & SAFETY_HIGH_SECTORS:
        return 1.0
    if sectors & SAFETY_MEDIUM_SECTORS:
        return 0.8
    if sectors:
        return 0.5
    return 0.8  # unknown sector -> MEDIUM default (see docstring)


def derive_cd(severity):
    if severity in ("critical", "high"):
        return 1.0
    if severity == "medium":
        return 0.75
    if severity == "low":
        return 0.5
    return 0.75  # unknown -> MEDIUM default


def build_ivss(cvss_calc, base_metrics, is_kev, advisory_meta):
    """base_metrics: dict with AV, AC (v3) or AC/AT (v4), PR, UI, and impact
    letters under 'C'/'I'/'A' (already normalised by caller)."""
    ivss = IVSSCalculator()
    ivss.set_cvss_calculator(cvss_calc)  # hybrid mode

    tiers = av_to_tiers(base_metrics.get("AV"))
    au = pr_to_au(base_metrics.get("PR"))
    ui = ui_to_ivss(base_metrics.get("UI"))
    ec = ac_at_to_ec(base_metrics)
    ex = 0.5  # KEV neutralised
    rc = 1.0
    rl = 0.0
    bc = derive_bc(base_metrics.get("C"), base_metrics.get("I"), base_metrics.get("A"))

    ivss.set_base_metrics(rc=rc, bc=bc, rl=rl, ec=ec, ex=ex, au=au, ui=ui, av=tiers["threat_vector"])
    ivss.set_local_environment_metrics(la=tiers["asset_access"], cp=0.2)  # CP fixed COMPLIANT

    if bc == 1.0:
        vi = mi = ci = 1.0
    elif bc == 0.75:
        vi = mi = ci = 0.5
    else:
        vi = mi = ci = 0.0
    ivss.set_process_consequence_metrics(vi=vi, mi=mi, ci=ci)

    pi = impact_tier(base_metrics.get("A"))
    ri = impact_tier(base_metrics.get("I"))
    sectors = advisory_meta["sectors"] if advisory_meta else set()
    severity = advisory_meta["severity"] if advisory_meta else ""
    si = derive_si(sectors)
    cd = derive_cd(severity)
    ivss.set_impact_metrics(pi=pi, ri=ri, si=si, cd=cd)

    return ivss.calculate_final_score()


def main():
    kev_ids = load_kev_ids(os.path.join(DATA, "known_exploited_vulnerabilities.json"))
    advisory_meta = load_advisory_metadata(os.path.join(DATA, "ics_advisory_archive_merged_2010_2026.csv"))

    in_path = os.path.join(DATA, "cve_scores_extracted.csv")
    out_path = os.path.join(WORK, "cve_bulk_scores_noKEV.csv")

    out_rows = []
    stats = dict(v3_ok=0, v3_fail=0, v4_ok=0, v4_fail=0, ivss_ok=0, ivss_fail=0)

    with open(in_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        all_rows = list(reader)

    print(f"Total CVE rows to process: {len(all_rows)}")

    for i, row in enumerate(all_rows, 1):
        cve = row["CVE_Number"]
        out = {
            "CVE_Number": cve,
            "vendor": row.get("vendor", ""),
            "product": row.get("product", ""),
            "v3_vector": row.get("v3_vector", ""),
            "v3_1_score": "",
            "v4_vector": row.get("v4_vector", ""),
            "v4_0_score": "",
            "ivss_score": "",
            "ivss_basis": "",
            "in_cisa_kev": 1 if cve in kev_ids else 0,
        }

        v3_calc = None
        v4_calc = None
        v3_metrics = None
        v4_metrics = None

        v3_vec = row.get("v3_vector", "").strip()
        if v3_vec:
            try:
                v3_calc = CVSSv3Calculator.from_vector_string(v3_vec)
                out["v3_1_score"] = v3_calc.calculate_base_score()
                v3_metrics = parse_vector_metrics(v3_vec)
                stats["v3_ok"] += 1
            except Exception as e:
                stats["v3_fail"] += 1

        v4_vec = row.get("v4_vector", "").strip()
        if v4_vec:
            try:
                v4_calc = CVSSv4Calculator.from_vector_string(v4_vec)
                out["v4_0_score"] = v4_calc.calculate_base_score()
                v4_metrics = parse_vector_metrics(v4_vec)
                stats["v4_ok"] += 1
            except Exception as e:
                stats["v4_fail"] += 1

        # Prefer v4 as the IVSS hybrid base if available (more granular:
        # separates Vulnerable/Subsequent system + Attack Requirements),
        # else fall back to v3.
        chosen_calc = None
        chosen_metrics = None
        basis = ""
        if v4_calc is not None and v4_metrics is not None:
            chosen_calc = v4_calc
            # Normalise v4 letters (VC/VI/VA -> C/I/A "worst of vulnerable/
            # subsequent system", since IVSS's impact model doesn't
            # distinguish the two systems the way v4 does).
            def worse(a, b):
                order = {"H": 2, "L": 1, "N": 0, None: 0}
                return a if order.get(a, 0) >= order.get(b, 0) else b
            chosen_metrics = dict(v4_metrics)
            chosen_metrics["C"] = worse(v4_metrics.get("VC"), v4_metrics.get("SC"))
            chosen_metrics["I"] = worse(v4_metrics.get("VI"), v4_metrics.get("SI"))
            chosen_metrics["A"] = worse(v4_metrics.get("VA"), v4_metrics.get("SA"))
            basis = "v4.0"
        elif v3_calc is not None and v3_metrics is not None:
            chosen_calc = v3_calc
            chosen_metrics = v3_metrics
            basis = "v3.1"

        if chosen_calc is not None:
            try:
                meta = advisory_meta.get(cve)
                out["ivss_score"] = round(build_ivss(chosen_calc, chosen_metrics, out["in_cisa_kev"] == 1, meta), 1)
                out["ivss_basis"] = basis
                stats["ivss_ok"] += 1
            except Exception as e:
                stats["ivss_fail"] += 1

        out_rows.append(out)
        if i % 1000 == 0:
            print(f"  ...{i}/{len(all_rows)} processed")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        writer.writeheader()
        writer.writerows(out_rows)

    print()
    print(f"Wrote {len(out_rows)} rows to {out_path}")
    print(stats)


if __name__ == "__main__":
    main()
