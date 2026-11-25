# Robustness analyses

Scripts behind the robustness checks in Sections 5.2.4 and 5.4 and the Appendix. They import the scoring code from
`../Project Code`, read corpus inputs from `../data` and simulation outputs from `../simulation_results`
(override with the `IVSS_PROJECT`, `IVSS_DATA` and `IVSS_SUPPORT` environment variables).

Requirement: `pip install 'cvss==3.6'`. Run any script with `python3 <script>.py` from this folder.

| Script | What it shows |
|---|---|
| `faithful_arch_factorial.py` | Architecture effect (Section 5.2.4): reproduces the assigned CP/LA gap (+2.128 = 0.600 segmentation + 1.528 asset access) and shows it falls to 0 when both modifiers are derived per device. |
| `validate_fixed_values.py` | Calibration of the assigned CP/LA values against the simulated inventories (Appendix Table on CP/LA), monotonicity sweep, CP x LA sensitivity. |
| `honest_gap_from_detection.py` | Asset access derived from each device's actual detection outcome: the architecture gap falls to about -0.07. |
| `multiseed_arch_gap.py` | Architecture gap across simulation seeds (needs per-seed ns-3 result folders, `--std` / `--hidden`). |
| `rbs_param.py`, `run_bulk_scoring_noKEV.py` | Corpus scoring with configurable fixed defaults (env `IVSS_CP`, `IVSS_RL`, `IVSS_RC`, `OUT`) and with the KEV-derived input neutralised. |
| `corpus_robustness.py` | Escalation/de-escalation under alternative defaults, population coverage, share of scores capped at 10.0. |
| `kev_robustness_check.py` | KEV circularity check (Section 5.4). |
| `coverage_by_sector_vendor.py` | Usable-vector coverage by year, sector and vendor (Appendix coverage table). |

Sanity check: `faithful_arch_factorial.py` with assigned values must give a standard-network gap of +2.1278 for every
vulnerability.
