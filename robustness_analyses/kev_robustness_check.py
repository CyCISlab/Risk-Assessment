#!/usr/bin/env python3
"""
kev_robustness_check.py

Robustness check for KEV circularity (Section 5.4):
"Algorithm 5 uses CISA KEV membership to set exploit maturity, then Section 5.4
presents higher scores for KEV-listed CVEs as construct-validity evidence; for
IVSS that comparison is not independent."

This script quantifies how much KEV actually affects the §5.4 corpus results,
using the project's own scoring outputs and the exact band() / pairing rule from
generate_real_cve_figures.py (v4.0 category where IVSS was based on v4, else v3.1).

It reports three things:
  (1) the published baseline (KEV in scoring)              -> reproduces 49.9% / 89.3%
  (2) KEV removed from SCORING (exploit-maturity neutralised, all 6,544 kept)
  (3) KEV rows dropped entirely (the 122 KEV CVEs excluded)

To produce the input for (2), make a one-line-patched copy of run_bulk_scoring.py:
    cp run_bulk_scoring.py run_bulk_scoring_noKEV.py
    # in run_bulk_scoring_noKEV.py, inside build_ivss(), change:
    #     ex = 1.0 if is_kev else 0.5
    # to:
    #     ex = 0.5            # KEV neutralised
    # and change the out_path filename to cve_bulk_scores_noKEV.csv
    python3 run_bulk_scoring_noKEV.py
Then run this script.  cve_bulk_scores_noKEV.csv is optional; if absent, only
(1) and (3) are reported.

Usage:
    python3 kev_robustness_check.py [cve_bulk_scores.csv] [cve_bulk_scores_noKEV.csv]
"""
import csv
import sys


def band(score):
    # EXACT band() from generate_real_cve_figures.py
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


ORD = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def load_pairs(path):
    """(base_cvss, ivss, is_kev) per CVE, using the same base-selection as the paper's figure script."""
    pairs = []
    for r in csv.DictReader(open(path, newline="", encoding="utf-8")):
        if not r["ivss_score"]:
            continue
        base = r["v4_0_score"] if r["ivss_basis"] == "v4.0" else r["v3_1_score"]
        if base:
            pairs.append((float(base), float(r["ivss_score"]), r["in_cisa_kev"] == "1", r["CVE_Number"]))
    return pairs


def report(sample, label):
    e = d = s = 0
    for a, b, k, cve in sample:
        ca, cb = ORD[band(a)], ORD[band(b)]
        if cb > ca:
            e += 1
        elif cb < ca:
            d += 1
        else:
            s += 1
    n = len(sample)
    disc = e + d
    print(f"{label}")
    print(f"  n={n}  escalate {e} ({100*e/n:.1f}%)  de-escalate {d} ({100*d/n:.1f}%)  "
          f"unchanged {s} ({100*s/n:.1f}%)  discordant-escalate {100*e/disc:.1f}%")


def main():
    base_csv = sys.argv[1] if len(sys.argv) > 1 else "cve_bulk_scores.csv"
    nokev_csv = sys.argv[2] if len(sys.argv) > 2 else "cve_bulk_scores_noKEV.csv"

    base = load_pairs(base_csv)
    print("=== (1) PAPER BASELINE (KEV in scoring) ===")
    report(base, "baseline")

    print("\n=== (3) KEV ROWS DROPPED (122 KEV CVEs excluded) ===")
    report([p for p in base if not p[2]], "KEV-rows-dropped")

    try:
        nok = load_pairs(nokev_csv)
    except FileNotFoundError:
        print(f"\n[note] {nokev_csv} not found; see header for how to generate it to run test (2).")
        return

    print("\n=== (2) KEV REMOVED FROM SCORING (exploit-maturity neutralised, all CVEs kept) ===")
    report(nok, "KEV-neutralised")

    # Per-CVE identity check
    bmap = {cve: b for a, b, k, cve in base}
    nmap = {cve: b for a, b, k, cve in nok}
    changed = [cve for cve in bmap if bmap[cve] != nmap.get(cve)]
    print(f"\nIVSS scores that change when KEV is removed from scoring: {len(changed)} of {len(bmap)}")
    if not changed:
        print("=> KEV membership has ZERO effect on any IVSS score (exploit-maturity feeds only the")
        print("   probability channel, which the hybrid final score does not use).")


if __name__ == "__main__":
    main()
