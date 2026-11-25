#!/usr/bin/env python3
"""
extract_cve_scores.py

Run this LOCALLY on your machine (no external packages needed, just
Python 3.6+ standard library). It reads the merged ICS advisory CSV and
your local cvelistV5 checkout, and produces one compact output CSV with
whatever CVSS v3.x / v4.0 vectors each CVE actually has published.

Usage:
    python3 extract_cve_scores.py \
        --csv ics_advisory_archive_merged_2010_2026.csv \
        --cvelist "path/to/cvelistV5-main/cves" \
        --out cve_scores_extracted.csv

--csv       Path to the merged ICS advisory archive CSV.
--cvelist   Path to the "cves" folder inside your cvelistV5-main checkout
            (the folder that directly contains 2010/, 2011/, ... 2026/ subfolders).
--out       Where to write the resulting summary CSV.

What it does:
  1. Reads every distinct CVE_Number from the advisory CSV.
  2. For each one, looks up <cvelist>/<year>/<bucket>xxx/<CVE-ID>.json
     (the standard cvelistV5 layout).
  3. Parses the CVE 5.x record and pulls out ANY CVSS v3.0/v3.1/v4.0
     metric it finds -- checking both the CNA container (the reporting
     vendor/researcher) and any ADP containers (e.g. NVD, which often
     adds its own CVSS assessment later even when the CNA didn't supply one).
  4. Writes one row per CVE to the output CSV with whatever it found.
     Missing data is left blank rather than guessed at.

This does NOT compute CVSS v3/v4 scores itself -- it only extracts the
already-published official vectors/scores exactly as they appear in the
CVE record, so nothing here involves any conversion or approximation.
Once you send the output CSV back, the actual v3.1/v4.0/IVSS scoring
against your project's calculators happens on my end.
"""

import argparse
import csv
import json
import os
import sys


def cve_json_path(cvelist_root, cve_id):
    # cve_id like CVE-2023-6448
    parts = cve_id.split('-')
    if len(parts) != 3 or parts[0] != 'CVE':
        return None
    year, num = parts[1], parts[2]
    try:
        bucket = int(num) // 1000
    except ValueError:
        return None
    return os.path.join(cvelist_root, year, f"{bucket}xxx", f"{cve_id}.json")


def extract_metrics(data):
    """Return list of dicts: {source, version, vectorString, baseScore}"""
    found = []

    def scan_metrics(metrics_list, source):
        if not metrics_list:
            return
        for m in metrics_list:
            for key, val in m.items():
                kl = key.lower()
                if 'cvssv4' in kl.replace('_', '').replace('.', ''):
                    found.append({
                        'source': source,
                        'version': '4.0',
                        'vectorString': val.get('vectorString'),
                        'baseScore': val.get('baseScore'),
                    })
                elif 'cvssv3' in kl.replace('_', '').replace('.', ''):
                    found.append({
                        'source': source,
                        'version': val.get('version', '3.x'),
                        'vectorString': val.get('vectorString'),
                        'baseScore': val.get('baseScore'),
                    })

    containers = data.get('containers', {})
    cna = containers.get('cna', {})
    scan_metrics(cna.get('metrics'), 'cna')

    adp_list = containers.get('adp', []) or []
    for adp in adp_list:
        title = adp.get('title') or adp.get('providerMetadata', {}).get('shortName', 'adp')
        scan_metrics(adp.get('metrics'), f"adp:{title}")

    return found


def best_of_version(metrics, version_prefix):
    """Prefer an ADP (usually NVD) entry over a CNA entry if both exist, since
    NVD-assigned scores are typically the more consistently-applied ones;
    otherwise take whatever is available."""
    candidates = [m for m in metrics if m['version'].startswith(version_prefix)]
    if not candidates:
        return None
    for m in candidates:
        if m['source'].startswith('adp'):
            return m
    return candidates[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', required=True, help='Path to merged ICS advisory CSV')
    ap.add_argument('--cvelist', required=True, help='Path to cvelistV5 "cves" root folder')
    ap.add_argument('--out', default='cve_scores_extracted.csv', help='Output CSV path')
    args = ap.parse_args()

    if not os.path.isdir(args.cvelist):
        print(f"ERROR: --cvelist path does not exist or is not a directory: {args.cvelist}", file=sys.stderr)
        sys.exit(1)

    cve_ids = set()
    with open(args.csv, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            for c in (row.get('CVE_Number') or '').split(','):
                c = c.strip()
                if c.startswith('CVE-'):
                    cve_ids.add(c)

    print(f"Distinct CVEs to look up: {len(cve_ids)}")

    rows = []
    found_count = 0
    missing_count = 0
    error_count = 0

    for i, cve_id in enumerate(sorted(cve_ids), 1):
        path = cve_json_path(args.cvelist, cve_id)
        row = {
            'CVE_Number': cve_id,
            'file_found': 0,
            'vendor': '',
            'product': '',
            'v3_version': '',
            'v3_vector': '',
            'v3_score': '',
            'v3_source': '',
            'v4_vector': '',
            'v4_score': '',
            'v4_source': '',
        }
        if not path or not os.path.isfile(path):
            missing_count += 1
            rows.append(row)
            if i % 500 == 0:
                print(f"  ...{i}/{len(cve_ids)} processed")
            continue

        try:
            with open(path, encoding='utf-8', errors='replace') as jf:
                data = json.load(jf)
        except Exception as e:
            error_count += 1
            rows.append(row)
            continue

        row['file_found'] = 1
        found_count += 1

        cna = data.get('containers', {}).get('cna', {})
        affected = cna.get('affected') or [{}]
        row['vendor'] = affected[0].get('vendor', '') if affected else ''
        row['product'] = affected[0].get('product', '') if affected else ''

        metrics = extract_metrics(data)
        v3 = best_of_version(metrics, '3')
        v4 = best_of_version(metrics, '4')
        if v3:
            row['v3_version'] = v3['version']
            row['v3_vector'] = v3['vectorString'] or ''
            row['v3_score'] = v3['baseScore'] if v3['baseScore'] is not None else ''
            row['v3_source'] = v3['source']
        if v4:
            row['v4_vector'] = v4['vectorString'] or ''
            row['v4_score'] = v4['baseScore'] if v4['baseScore'] is not None else ''
            row['v4_source'] = v4['source']

        rows.append(row)
        if i % 500 == 0:
            print(f"  ...{i}/{len(cve_ids)} processed")

    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Done. Wrote {len(rows)} rows to {args.out}")
    print(f"  Files found locally: {found_count}")
    print(f"  Files NOT found locally (year folder not downloaded/connected, or reserved CVE): {missing_count}")
    print(f"  Files that failed to parse: {error_count}")
    has_v3 = sum(1 for r in rows if r['v3_vector'])
    has_v4 = sum(1 for r in rows if r['v4_vector'])
    print(f"  Rows with a v3.x vector: {has_v3}")
    print(f"  Rows with a v4.0 vector: {has_v4}")


if __name__ == '__main__':
    main()
