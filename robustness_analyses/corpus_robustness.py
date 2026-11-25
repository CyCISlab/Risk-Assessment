#!/usr/bin/env python3
"""
corpus_robustness.py

Corpus-level robustness checks for Section 5.4, all pure-Python
on the bulk-scoring output (no NS-3):

  (A-Q3) default sensitivity : re-score with rbs_param.py under varied fixed
                               defaults, then pass each CSV here to see how the
                               escalation asymmetry moves.
  (A)    population coverage  : usable vs excluded by year-period and vendor.
  (B)    hybrid ceiling       : share of scores that clip at 10.0.

Default sensitivity is produced with rbs_param.py (a copy of run_bulk_scoring.py
whose fixed defaults read environment variables):
    OUT=seg075.csv IVSS_CP=0.75 python3 rbs_param.py
    OUT=rl10.csv   IVSS_RL=1.0  python3 rbs_param.py
    OUT=rc05.csv   IVSS_RC=0.5  python3 rbs_param.py
then:
    python3 corpus_robustness.py cve_bulk_scores.csv seg075.csv rl10.csv rc05.csv

With one CSV it prints population + ceiling only.
"""
import csv
import re
import sys
from collections import Counter


def band(s):
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


ORD = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def escalation(path):
    e = d = s = 0
    for r in csv.DictReader(open(path)):
        if not r["ivss_score"]:
            continue
        base = r["v4_0_score"] if r["ivss_basis"] == "v4.0" else r["v3_1_score"]
        if not base:
            continue
        a, b = ORD[band(float(base))], ORD[band(float(r["ivss_score"]))]
        if b > a:
            e += 1
        elif b < a:
            d += 1
        else:
            s += 1
    n = e + d + s
    disc = e + d
    return n, 100 * e / n, 100 * d / n, (100 * e / disc if disc else 0)


def year(cve):
    m = re.match(r"CVE-(\d{4})-", cve)
    return int(m.group(1)) if m else None


def period(y):
    if y is None:
        return "unknown"
    if y <= 2016:
        return "2010-2016"
    if y <= 2021:
        return "2017-2021"
    return "2022-2026"


def population_and_ceiling(path):
    rows = list(csv.DictReader(open(path)))
    U = [r for r in rows if r["ivss_score"]]
    X = [r for r in rows if not r["ivss_score"]]
    print(f"\n=== population coverage ({path}) ===")
    print(f"TOTAL {len(rows)}  usable {len(U)} ({100*len(U)/len(rows):.1f}%)  excluded {len(X)}")
    for p in ["2010-2016", "2017-2021", "2022-2026"]:
        u = sum(1 for r in U if period(year(r["CVE_Number"])) == p)
        x = sum(1 for r in X if period(year(r["CVE_Number"])) == p)
        tot = u + x
        print(f"  {p}: {u} usable / {tot} total -> {100*u/tot:.0f}% coverage")
    print("  top vendors (usable):", ", ".join(f"{v}={c}" for v, c in
          Counter((r['vendor'] or 'n/a') for r in U).most_common(6)))
    base = lambda r: r["v4_0_score"] if r["ivss_basis"] == "v4.0" else r["v3_1_score"]
    clip = [r for r in U if float(r["ivss_score"]) == 10.0]
    frommax = [r for r in clip if base(r) and float(base(r)) == 10.0]
    print(f"=== hybrid ceiling: {len(clip)}/{len(U)} ({100*len(clip)/len(U):.1f}%) clip at 10.0; "
          f"{len(frommax)} start from CVSS base 10.0 ===")


def main():
    paths = sys.argv[1:] or ["cve_bulk_scores.csv"]
    if len(paths) > 1:
        print(f"{'CSV':<24}{'n':>6}{'escalate%':>10}{'deesc%':>8}{'disc-esc%':>10}")
        for p in paths:
            n, e, d, disc = escalation(p)
            print(f"{p:<24}{n:>6}{e:>10.1f}{d:>8.1f}{disc:>10.1f}")
    population_and_ceiling(paths[0])


if __name__ == "__main__":
    main()
