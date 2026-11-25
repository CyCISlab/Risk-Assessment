"""
Common Vulnerability Scoring System v3.1

Implements CVSS v3.1 base/temporal scoring for direct comparison against
CVSSv4Calculator (scoring/cvss_calculator.py) and IVSSCalculator
(scoring/ivss_calculator.py).

Design note: this class mirrors CVSSv4Calculator's interface deliberately
(set_base_metrics / set_threat_metrics / set_environmental_metrics /
calculate_base_score / calculate_probability / calculate_impact /
calculate_risk) so the same calling code and comparison utilities can drive
CVSS v3.1, CVSS v4.0, and IVSS side by side.

Like CVSSv4Calculator, calculate_base_score() delegates the actual score
computation to FIRST.org's official, community-vetted reference
implementation (the `cvss` PyPI package, https://pypi.org/project/cvss/)
rather than a hand-rolled formula. This class does not attempt to
re-derive the CVSS v3.1 base/temporal equations itself, for the same
reason CVSSv4Calculator no longer does: a self-written reimplementation is
an easy place to introduce a subtle, hard-to-notice scoring bug (as the
original CVSSv4Calculator interpolation code did -- see the docstring on
CVSSv4Calculator.calculate_base_score for that history), and there is no
benefit to re-deriving a formula FIRST.org and the wider community have
already published and validated.

calculate_probability() / calculate_impact() / calculate_risk() are NOT
part of the official CVSS v3.1 specification -- they are this project's
own component-level (probability/impact/risk) decomposition, kept
consistent in spirit and weighting with CVSSv4Calculator's decomposition
of the same name so scores are comparable across CVSS versions and IVSS.

N,A,L,P etc. are not used in the final calculation. We used CVSS v3 and v4.
"""

from cvss import CVSS3


class CVSSv3Calculator:
    """
    Calculator for Common Vulnerability Scoring System (CVSS) v3.1.

    Provides the same shape of interface as CVSSv4Calculator so callers
    (scenario scripts, comparison utilities) can score a vulnerability
    under CVSS v3.1 and CVSS v4.0 with parallel code paths.
    """

    # Base metrics possible values
    AV_NETWORK = 'N'
    AV_ADJACENT = 'A'
    AV_LOCAL = 'L'
    AV_PHYSICAL = 'P'

    AC_LOW = 'L'
    AC_HIGH = 'H'

    PR_NONE = 'N'
    PR_LOW = 'L'
    PR_HIGH = 'H'

    UI_NONE = 'N'
    UI_REQUIRED = 'R'

    SCOPE_UNCHANGED = 'U'
    SCOPE_CHANGED = 'C'

    IMPACT_NONE = 'N'
    IMPACT_LOW = 'L'
    IMPACT_HIGH = 'H'

    # Temporal: Exploit Code Maturity
    E_NOT_DEFINED = 'X'
    E_UNPROVEN = 'U'
    E_POC = 'P'
    E_FUNCTIONAL = 'F'
    E_HIGH = 'H'

    # Temporal: Remediation Level
    RL_NOT_DEFINED = 'X'
    RL_OFFICIAL_FIX = 'O'
    RL_TEMPORARY_FIX = 'T'
    RL_WORKAROUND = 'W'
    RL_UNAVAILABLE = 'U'

    # Temporal: Report Confidence
    RC_NOT_DEFINED = 'X'
    RC_UNKNOWN = 'U'
    RC_REASONABLE = 'R'
    RC_CONFIRMED = 'C'

    def __init__(self):
        """Initialise the CVSS v3.1 calculator with empty metrics."""
        self.metrics = {
            # Base - Exploitability
            'AV': None,
            'AC': None,
            'PR': None,
            'UI': None,
            'S': None,
            # Base - Impact
            'C': None,
            'I': None,
            'A': None,
            # Temporal (optional)
            'E': None,
            'RL': None,
            'RC': None,
            # Environmental requirements (optional, default Not Defined -> High per spec)
            'CR': None,
            'IR': None,
            'AR': None,
        }

    def set_base_metrics(self, av, ac, pr, ui, s, c, i, a):
        """
        Set all Base metrics at once.

        Args:
            av (str): Attack Vector (N/A/L/P)
            ac (str): Attack Complexity (L/H)
            pr (str): Privileges Required (N/L/H)
            ui (str): User Interaction (N/R)
            s (str): Scope (U/C)
            c (str): Confidentiality Impact (N/L/H)
            i (str): Integrity Impact (N/L/H)
            a (str): Availability Impact (N/L/H)

        Returns:
            CVSSv3Calculator: Self for method chaining
        """
        self.metrics['AV'] = av
        self.metrics['AC'] = ac
        self.metrics['PR'] = pr
        self.metrics['UI'] = ui
        self.metrics['S'] = s
        self.metrics['C'] = c
        self.metrics['I'] = i
        self.metrics['A'] = a
        return self

    def set_threat_metrics(self, e=None, rl=None, rc=None):
        """
        Set Temporal metrics.

        Args:
            e (str, optional): Exploit Code Maturity
            rl (str, optional): Remediation Level
            rc (str, optional): Report Confidence

        Returns:
            CVSSv3Calculator: Self for method chaining
        """
        if e is not None:
            self.metrics['E'] = e
        if rl is not None:
            self.metrics['RL'] = rl
        if rc is not None:
            self.metrics['RC'] = rc
        return self

    def set_environmental_metrics(self, cr=None, ir=None, ar=None):
        """
        Set Environmental Security Requirement metrics.

        Args:
            cr (str, optional): Confidentiality Requirement (L/M/H)
            ir (str, optional): Integrity Requirement (L/M/H)
            ar (str, optional): Availability Requirement (L/M/H)

        Returns:
            CVSSv3Calculator: Self for method chaining
        """
        if cr is not None:
            self.metrics['CR'] = cr
        if ir is not None:
            self.metrics['IR'] = ir
        if ar is not None:
            self.metrics['AR'] = ar
        return self

    def to_vector_string(self):
        """
        Convert current metrics to a CVSS v3.1 vector string.

        Returns:
            str: CVSS v3.1 vector string
        """
        parts = ["CVSS:3.1"]

        for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            if self.metrics[metric] is None:
                raise ValueError(f"Metric {metric} must be set before building the vector string")
            parts.append(f"{metric}:{self.metrics[metric]}")

        for metric in ['E', 'RL', 'RC', 'CR', 'IR', 'AR']:
            value = self.metrics.get(metric)
            if value is not None and value != 'X':
                parts.append(f"{metric}:{value}")

        return "/".join(parts)

    @classmethod
    def from_vector_string(cls, vector_string):
        """
        Create a calculator instance from a CVSS v3.1 vector string.

        Args:
            vector_string (str): CVSS v3.1 vector string (e.g. from NVD)

        Returns:
            CVSSv3Calculator: Calculator instance with metrics from vector string
        """
        if not (vector_string.startswith("CVSS:3.1") or vector_string.startswith("CVSS:3.0")):
            raise ValueError("Vector string must start with CVSS:3.0 or CVSS:3.1")

        calculator = cls()
        parts = vector_string.split("/")[1:]
        for part in parts:
            try:
                metric, value = part.split(":")
            except ValueError:
                raise ValueError(f"Invalid metric format: {part}")
            if metric not in calculator.metrics:
                raise ValueError(f"Unknown metric: {metric}")
            calculator.metrics[metric] = value

        for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            if calculator.metrics[metric] is None:
                raise ValueError(f"Missing mandatory metric: {metric}")

        return calculator

    def calculate_base_score(self):
        """
        Calculate the CVSS v3.1 score.

        Returns the Base score if no Temporal/Environmental metrics are
        set, otherwise the Temporal or Environmental score (matching the
        official calculator's own behaviour, and mirroring how
        CVSSv4Calculator.calculate_base_score folds in E/CR/IR/AR when
        present).

        Returns:
            float: Score (0.0-10.0)
        """
        for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            if self.metrics[metric] is None:
                raise ValueError(f"Metric {metric} must be set before calculating the score")

        vector_string = self.to_vector_string()
        official = CVSS3(vector_string)

        if self.metrics.get('CR') or self.metrics.get('IR') or self.metrics.get('AR'):
            return round(float(official.environmental_score), 1)
        if self.metrics.get('E') or self.metrics.get('RL') or self.metrics.get('RC'):
            return round(float(official.temporal_score), 1)
        return round(float(official.base_score), 1)

    def calculate_probability(self):
        """
        Extract probability factors from CVSS v3.1 exploitability metrics.

        Mirrors CVSSv4Calculator.calculate_probability's weighting
        philosophy (this project's own risk-decomposition heuristic, not
        part of the official CVSS specification) so v3.1 and v4.0
        probability components are comparable.

        Returns:
            float: A probability value between 0-1
        """
        required_metrics = ['AV', 'AC', 'PR', 'UI']
        for metric in required_metrics:
            if self.metrics[metric] is None:
                raise ValueError(f"Metric {metric} must be set before calculating probability")

        weights = {
            'AV': 0.30,
            'AC': 0.25,
            'PR': 0.25,
            'UI': 0.10,
            'E': 0.10,
        }
        scores = {
            'AV': {'N': 1.0, 'A': 0.7, 'L': 0.4, 'P': 0.2},
            'AC': {'L': 1.0, 'H': 0.4},
            'PR': {'N': 1.0, 'L': 0.6, 'H': 0.3},
            'UI': {'N': 1.0, 'R': 0.5},
            'E': {'H': 1.0, 'F': 0.9, 'P': 0.7, 'U': 0.5, 'X': 0.8},
        }

        e_value = self.metrics.get('E') or 'X'

        total_score = 0.0
        total_weight = 0.0
        for metric in required_metrics:
            if self.metrics[metric] in scores[metric]:
                total_score += weights[metric] * scores[metric][self.metrics[metric]]
                total_weight += weights[metric]
        if e_value in scores['E']:
            total_score += weights['E'] * scores['E'][e_value]
            total_weight += weights['E']

        return total_score / total_weight if total_weight > 0 else 0.5

    def calculate_impact(self):
        """
        Extract impact factors from CVSS v3.1 impact metrics, accounting
        for Scope the way the official ISC-to-impact-subscore formula does
        (Scope:Changed applies a different combining formula than
        Scope:Unchanged, per the v3.1 specification).

        This is this project's own 0-10 impact decomposition (mirroring
        CVSSv4Calculator.calculate_impact), not an official CVSS output.

        Returns:
            float: An impact value between 0-10
        """
        required_metrics = ['C', 'I', 'A', 'S']
        for metric in required_metrics:
            if self.metrics[metric] is None:
                raise ValueError(f"Metric {metric} must be set before calculating impact")

        impact_scores = {'N': 0.0, 'L': 0.22, 'H': 0.56}

        c_value = impact_scores.get(self.metrics['C'], 0)
        i_value = impact_scores.get(self.metrics['I'], 0)
        a_value = impact_scores.get(self.metrics['A'], 0)

        isc_base = 1 - ((1 - c_value) * (1 - i_value) * (1 - a_value))

        if self.metrics['S'] == 'C':
            # Scope Changed: larger multiplier and offset, matching the
            # relative shape of the official v3.1 Scope:Changed formula.
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            isc = 6.42 * isc_base

        return min(10.0, max(0.0, isc))

    def calculate_risk(self):
        """
        Calculate Risk = Probability x Impact, on a 0-10 scale, for
        direct comparison against CVSSv4Calculator.calculate_risk and
        IVSSCalculator's risk output.

        Returns:
            float: Risk score on 0-10 scale
        """
        probability = self.calculate_probability()
        impact = self.calculate_impact()
        return round(probability * impact, 1)
