#!/usr/bin/env python3
"""
multiseed_arch_gap.py

Multi-seed robustness check for the network-architecture effect ("single-seed runs").  The paper reports the standard - edge/hidden IVSS gap from
one seed per architecture; this script aggregates that gap across several seeds
and reports mean +/- SD, so you can state whether the single-seed figure is
representative.

It does NOT run NS-3.  Run the simulations yourself first, e.g.:

    for s in 1 2 3 4 5; do
      SIM_SEED=$s RESULTS_DIR=results/standard_s$s python3 main.py --sim standard_network
      SIM_SEED=$s RESULTS_DIR=results/hidden_s$s   python3 main.py --sim edge_hidden_network
    done

then:

    python3 multiseed_arch_gap.py --std 'results/standard_s*' --hidden 'results/hidden_s*'

Each run writes assessment_results.json (keyed by vulnerability, each with
vulnerability_data.{cvss_score, standalone_ivss_score, hybrid_ivss_score}).
The script pairs standard/edge seeds in sorted order, computes the per-seed mean
IVSS in each network, the per-seed gap (standard - edge/hidden), and the across-
seed mean +/- SD, for both standalone IVSS and the hybrid.
"""
import argparse
import glob
import json
import os
import statistics as st


def find_results(dir_or_glob):
    """Return assessment_results.json paths under each matched directory, sorted."""
    paths = []
    for d in sorted(glob.glob(dir_or_glob)):
        hits = glob.glob(os.path.join(d, "**", "assessment_results.json"), recursive=True)
        if not hits:
            direct = os.path.join(d, "assessment_results.json")
            if os.path.exists(direct):
                hits = [direct]
        if hits:
            paths.append(sorted(hits)[0])
        else:
            print(f"[warn] no assessment_results.json under {d}")
    return paths


def mean_scores(results_file):
    """Return (mean_cvss, mean_standalone_ivss, mean_hybrid) over the vulnerabilities in one run."""
    with open(results_file) as f:
        data = json.load(f)
    cvss, ivss, hyb = [], [], []
    for _, v in data.items():
        vi = v.get("vulnerability_data", v)  # tolerate either nesting
        if "cvss_score" in vi:
            cvss.append(float(vi.get("cvss_score", 0)))
            ivss.append(float(vi.get("standalone_ivss_score", 0)))
            hyb.append(float(vi.get("hybrid_ivss_score", 0)))
    m = lambda xs: (sum(xs) / len(xs)) if xs else float("nan")
    return m(cvss), m(ivss), m(hyb), len(cvss)


def report(std_files, hid_files):
    n = min(len(std_files), len(hid_files))
    if n == 0:
        print("No paired runs found. Check --std/--hidden globs.")
        return
    print(f"Paired seeds: {n}\n")
    gap_ivss, gap_hyb = [], []
    print(f"{'seed#':<6}{'std IVSS':>10}{'edge IVSS':>11}{'gap IVSS':>10}"
          f"{'std hyb':>10}{'edge hyb':>10}{'gap hyb':>9}")
    for i in range(n):
        sc, si, sh, sn = mean_scores(std_files[i])
        hc, hi, hh, hn = mean_scores(hid_files[i])
        gi, gh = si - hi, sh - hh
        gap_ivss.append(gi)
        gap_hyb.append(gh)
        print(f"{i+1:<6}{si:>10.3f}{hi:>11.3f}{gi:>10.3f}{sh:>10.3f}{hh:>10.3f}{gh:>9.3f}")
    print()

    def summarise(label, gaps):
        mean = st.mean(gaps)
        sd = st.pstdev(gaps) if len(gaps) > 1 else 0.0
        print(f"{label}: gap = {mean:.3f} +/- {sd:.3f} (mean +/- SD over {len(gaps)} seeds)")
        if sd < 0.05:
            print(f"   -> SD < 0.05: single-seed value is representative; the effect is seed-insensitive.")
        else:
            print(f"   -> report the band; the effect varies with seed.")

    summarise("Standalone IVSS", gap_ivss)
    summarise("Hybrid        ", gap_hyb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--std", required=True, help="glob for standard-network result dirs, e.g. 'results/standard_s*'")
    ap.add_argument("--hidden", required=True, help="glob for edge/hidden-network result dirs, e.g. 'results/hidden_s*'")
    args = ap.parse_args()
    report(find_results(args.std), find_results(args.hidden))


if __name__ == "__main__":
    main()
