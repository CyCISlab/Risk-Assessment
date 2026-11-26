# Additions

These files extend the repository. The existing framework (`Project Code/`), corpus inputs and scored corpus
(`cve_scores_extracted.csv`, `ics_advisory_archive_merged_2010_2026.csv`, `known_exploited_vulnerabilities.json`,
`cve_bulk_scores.csv`) and the yearly advisory CSVs are used as they are.

| Path | Contents | Paper |
|---|---|---|
| `Project Code/scoring/ivss_calculator.py` | Updated: the segmentation penalty uses the monotonic test (`CP >= PARTIAL`); explanatory comments tidied. No reported number changes (the corpus uses CP = 0.2, and the simulated CP values trigger the penalty identically) | Section 4.2, Appendix |
| `Project Code/scoring/cvss3_calculator.py` | Docstring note only | Section 4.4 |
| `Project Code/extract_cve_scores.py` | Extracts published CVSS v3.x/v4.0 vectors from a CVE List V5 checkout | Section 5.4, Algorithm 4 |
| `run_bulk_scoring.py` | Corpus scoring pipeline: writes `cve_bulk_scores_rerun.csv`, which reproduces `cve_bulk_scores.csv` | Section 5.4, Algorithm 6 |
| `simulation_results/` | ns-3 outputs for both networks (per-device ground truth and passive-discovery results), score differences, sensitivity and performance data, simulation figures | Sections 5.2, 5.3 |
| `corpus_validation/` | Standalone IVSS vs hybrid, mapping and default sweeps, KEV and SSVC validation, CVSS environmental baseline, IVSS-specification weights, oracle-vs-passive discovery, Figure 7, SSVC snapshot (`ssvc.json`) | Section 5.4 (Table 5), Section 5.2.4 (Table 4), Figure 7 |
| `robustness_analyses/` | Architecture-effect decomposition, calibration checks, KEV circularity, corpus defaults and coverage | Sections 5.2.4, 5.4, Appendix |

## Quick start (from the repository root)

    pip install 'cvss==3.6' numpy scikit-learn matplotlib
    python3 run_bulk_scoring.py           # re-score the corpus (49.9% escalation, 6.0% de-escalation)
    cd corpus_validation
    python3 run_all.py                    # sweeps + environmental baseline -> sweep_results.json, scores.npz
    python3 validate_signals.py           # KEV / SSVC ROC-AUC with bootstrap CIs (Table 5)
    python3 speccheck.py                  # standalone IVSS with the IVSS-specification weights
    python3 oracle_check.py               # Table 4: passive discovery vs ground truth
    cd figures && python3 make_fig8.py    # Figure 7

Analyses use 6,531 CVEs: 13 CVSS v4.0 vectors do not parse with cvss 3.6 (all percentages are unchanged).
`extract_cve_scores.py` needs a local checkout of https://github.com/CVEProject/cvelistV5.
