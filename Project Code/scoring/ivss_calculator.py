"""
Industrial Vulnerability Scoring System (IVSS) Calculator

Provides specialised vulnerability scoring for industrial control systems
that builds upon standard CVSS scoring with ICS environmental factors.
"""

class IVSSCalculator:
    """Calculator for Industrial Vulnerability Scoring System (IVSS)."""
    
    # Base metrics constants
    REPORT_CONFIDENCE_UNCONFIRMED = 0.25
    REPORT_CONFIDENCE_UNCORROBORATED = 0.5
    REPORT_CONFIDENCE_CONFIRMED = 1.0
    REPORT_CONFIDENCE_NOT_DEFINED = 1.0
    
    CONSEQUENCE_TEMPORARY_DENIAL = 0.25
    CONSEQUENCE_DATA_MODIFICATION = 0.5
    CONSEQUENCE_SUSTAINED_DENIAL = 0.75
    CONSEQUENCE_CONTROL = 1.0
    
    REMEDIATION_LEVEL_OFFICIAL_FIX = 0.0
    REMEDIATION_LEVEL_WORKAROUND = 0.75
    REMEDIATION_LEVEL_TEMPORARY_FIX = 0.9
    REMEDIATION_LEVEL_UNAVAILABLE = 1.0
    REMEDIATION_LEVEL_NOT_DEFINED = 1.0
    
    EXPLOIT_DIFFICULTY_HIGH = 0.2
    EXPLOIT_DIFFICULTY_MODERATE = 0.5
    EXPLOIT_DIFFICULTY_LOW = 1.0
    
    EXPLOIT_MATURITY_UNPROVEN = 0.5
    EXPLOIT_MATURITY_POC = 0.75
    EXPLOIT_MATURITY_FUNCTIONAL = 1.0
    EXPLOIT_MATURITY_NOT_DEFINED = 1.0
    
    PRIVILEGE_LEVEL_ADMIN_ROOT = 0.2
    PRIVILEGE_LEVEL_USER = 0.56
    PRIVILEGE_LEVEL_NONE = 1.0
    
    USER_INTERACTION_YES = 0.3
    USER_INTERACTION_NO = 1.0
    
    THREAT_VECTOR_LOCAL_HOST = 0.1
    THREAT_VECTOR_LOCAL_NETWORK = 0.5
    THREAT_VECTOR_ADJACENT_REMOTE = 1.0
    THREAT_VECTOR_UNDEFINED = 1.0
    
    ASSET_ACCESS_LOCAL_HOST = 0.25
    ASSET_ACCESS_LOCAL_NETWORK = 0.5
    ASSET_ACCESS_ADJACENT_REMOTE = 1.0
    
    NETWORK_SEGMENTATION_COMPLIANT = 0.2
    NETWORK_SEGMENTATION_PARTIAL = 0.75
    NETWORK_SEGMENTATION_DMZ_ONLY = 0.85
    NETWORK_SEGMENTATION_NONE = 1.0
    
    # Local ICS Environment metrics
    PROCESS_VISIBILITY_NONE = 0.0
    PROCESS_VISIBILITY_PARTIAL = 0.5
    PROCESS_VISIBILITY_COMPLETE = 1.0
    
    PROCESS_MONITORING_NONE = 0.0
    PROCESS_MONITORING_PARTIAL = 0.5
    PROCESS_MONITORING_COMPLETE = 1.0
    
    PROCESS_CONTROL_NONE = 0.0
    PROCESS_CONTROL_PARTIAL = 0.5 
    PROCESS_CONTROL_COMPLETE = 1.0
    
    # Impact metrics 
    SYSTEM_PRODUCTION_IMPACT_NONE = 0.0
    SYSTEM_PRODUCTION_IMPACT_LOW = 0.4
    SYSTEM_PRODUCTION_IMPACT_MEDIUM = 0.7
    SYSTEM_PRODUCTION_IMPACT_HIGH = 1.0
    SYSTEM_PRODUCTION_IMPACT_NOT_DEFINED = 1.0
    
    SYSTEM_RELIABILITY_IMPACT_NONE = 0.0
    SYSTEM_RELIABILITY_IMPACT_LOW = 0.33
    SYSTEM_RELIABILITY_IMPACT_MEDIUM = 0.66
    SYSTEM_RELIABILITY_IMPACT_HIGH = 1.0
    SYSTEM_RELIABILITY_IMPACT_NOT_DEFINED = 1.0
    
    SYSTEM_SAFETY_IMPACT_NONE = 0.0
    SYSTEM_SAFETY_IMPACT_LOW = 0.5
    SYSTEM_SAFETY_IMPACT_MEDIUM = 0.8
    SYSTEM_SAFETY_IMPACT_HIGH = 1.0
    SYSTEM_SAFETY_IMPACT_NOT_DEFINED = 1.0
    
    FINANCIAL_LOSS_IMPACT_NONE = 0.0 
    FINANCIAL_LOSS_IMPACT_LOW = 0.5 
    FINANCIAL_LOSS_IMPACT_LOW_MEDIUM = 0.75
    FINANCIAL_LOSS_IMPACT_MEDIUM_HIGH = 0.9
    FINANCIAL_LOSS_IMPACT_HIGH = 1.0
    FINANCIAL_LOSS_IMPACT_NOT_DEFINED = 1.0
    
    def __init__(self):
        """Initialise IVSS calculator with empty metrics."""
        self.metrics = {
            # Base severity & exploitability
            'RC': None,  # Report Confidence
            'BC': None,  # Consequence
            'RL': None,  # Remediation Level
            
            'EC': None,  # Exploit Difficulty/Incident Complexity
            'EX': None,  # Exploit Maturity
            'AU': None,  # Privilege Level Required
            'UI': None,  # User Interaction Required
            
            'AV': None,  # Threat Vector Required
            
            # Local ICS environment
            'LA': None,  # Asset Access
            'CP': None,  # Network Segmentation Level
            
            'VI': None,  # Process Visibility Consequence
            'MI': None,  # Process Monitoring Consequence
            'CI': None,  # Process Control Consequences
            
            'PI': None,  # System Production Impact
            'RI': None,  # System Reliability Impact
            'SI': None,  # System Safety Impact
            'CD': None,  # Financial Loss Impact
        }
        
        # Scores
        self.scores = {
            'BS': None,   # Base Severity
            'BEX': None,  # Base Exploitability
            'ACC': None,  # Local Accessibility
            'CON': None,  # Consequences
            'IMP': None,  # Impact
            'ADJACC': None,  # Adjusted Accessibility
            'ADJIMP': None,  # Adjusted Criticality
            'FINAL': None,  # Final Score
            'ORIGINAL_CVSS': None,  # Original CVSS score before modification
            'MODIFIER_IMPACT': None,  # Impact of IVSS modifiers on score
        }
        
        # Configuration flags
        self.use_external_cvss = False
        self.external_cvss_score = None
        self.cvss_calculator = None
        self.use_cvss_calculator = False
        self.adjustment_method = 'balanced'  # 'balanced', 'aggressive', 'conservative'

    def set_base_metrics(self, rc=None, bc=None, rl=None, ec=None, ex=None, au=None, ui=None, av=None):
        """Set base metrics, allowing for partial updates."""
        if rc is not None: self.metrics['RC'] = rc
        if bc is not None: self.metrics['BC'] = bc
        if rl is not None: self.metrics['RL'] = rl
        if ec is not None: self.metrics['EC'] = ec
        if ex is not None: self.metrics['EX'] = ex
        if au is not None: self.metrics['AU'] = au
        if ui is not None: self.metrics['UI'] = ui
        if av is not None: self.metrics['AV'] = av
        return self

    def set_local_environment_metrics(self, la=None, cp=None):
        """Set local environment metrics."""
        if la is not None: self.metrics['LA'] = la
        if cp is not None: self.metrics['CP'] = cp
        return self

    def set_process_consequence_metrics(self, vi=None, mi=None, ci=None):
        """Set process consequence metrics."""
        if vi is not None: self.metrics['VI'] = vi
        if mi is not None: self.metrics['MI'] = mi
        if ci is not None: self.metrics['CI'] = ci
        return self

    def set_impact_metrics(self, pi=None, ri=None, si=None, cd=None):
        """Set impact metrics."""
        if pi is not None: self.metrics['PI'] = pi
        if ri is not None: self.metrics['RI'] = ri
        if si is not None: self.metrics['SI'] = si
        if cd is not None: self.metrics['CD'] = cd
        return self
        
    def set_cvss_base_score(self, cvss_score):
        """
        Set base score from external CVSS score.
        
        Allows using existing CVSS scores with IVSS environmental modifiers.
        
        Args:
            cvss_score: CVSS base score (0-10)
        """
        self.use_external_cvss = True
        self.external_cvss_score = cvss_score
        self.scores['ORIGINAL_CVSS'] = cvss_score
        return self
    
    def set_cvss_calculator(self, cvss_calculator):
        """
        Set a CVSS calculator instance to use as base.
        
        This provides more flexibility than just setting a base score.
        
        Args:
            cvss_calculator: Instance of CVSSv4Calculator
        """
        self.use_cvss_calculator = True
        self.cvss_calculator = cvss_calculator
        self.external_cvss_score = cvss_calculator.calculate_base_score()
        self.scores['ORIGINAL_CVSS'] = self.external_cvss_score
        return self
    
    def set_adjustment_method(self, method):
        """
        Set the method for adjusting CVSS scores with IVSS modifiers.
        
        Args:
            method: String indicating adjustment approach
                'balanced' - Balanced approach (default)
                'aggressive' - More weight to industrial factors
                'conservative' - Less weight to industrial factors
        """
        valid_methods = ['balanced', 'aggressive', 'conservative']
        if method not in valid_methods:
            raise ValueError(f"Adjustment method must be one of: {valid_methods}")
        
        self.adjustment_method = method
        return self

    def calculate_base_severity_score(self):
        """Calculate Base Severity (BS) score."""
        # If using external CVSS score, return it
        if self.use_external_cvss or self.use_cvss_calculator:
            self.scores['BS'] = self.external_cvss_score
            return self.external_cvss_score
            
        rc = self.metrics['RC']
        bc = self.metrics['BC']
        rl = self.metrics['RL']
        
        if any(m is None for m in [rc, bc, rl]):
            raise ValueError("All base severity metrics must be set")
        
        # Formula: ((RC+BC*3+RL)/5)*10
        score = ((rc + bc * 3 + rl) / 5) * 10
        self.scores['BS'] = score
        return score

    def calculate_base_exploitability_score(self):
        """Calculate Base Exploitability (BEX) score."""
        # If using CVSS calculator, use its probability calculation
        if self.use_cvss_calculator and hasattr(self.cvss_calculator, 'calculate_probability'):
            prob = self.cvss_calculator.calculate_probability()
            score = prob * 10  # Convert probability (0-1) to score (0-10)
            self.scores['BEX'] = score
            return score
        
        ec = self.metrics['EC']
        ex = self.metrics['EX']
        au = self.metrics['AU']
        ui = self.metrics['UI']
        
        if any(m is None for m in [ec, ex, au, ui]):
            raise ValueError("All exploitability metrics must be set")
        
        # Formula: ((EC+EX+AU+UI)/4)*10
        score = ((ec + ex + au + ui) / 4) * 10
        self.scores['BEX'] = score
        return score
        
    def calculate_base_accessibility_score(self):
        """Calculate Base Accessibility Score based on Threat Vector Required."""
        av = self.metrics['AV']
        
        if av is None:
            raise ValueError("Threat Vector Required metric must be set")
            
        # Formula: AV*10
        score = av * 10
        return score
        
    def calculate_total_base_score(self):
        """Calculate Total Base Score."""
        # If using external CVSS score, return it
        if self.use_external_cvss or self.use_cvss_calculator:
            return self.external_cvss_score
            
        bs = self.calculate_base_severity_score()
        bex = self.calculate_base_exploitability_score()
        av = self.metrics['AV']
        
        if av is None:
            raise ValueError("Threat Vector Required metric must be set")
            
        # Formula: ((BS+BEX+(AV*2))/4)
        score = (bs + bex + (av * 2)) / 4
        return score

    def calculate_local_accessibility(self):
        """Calculate Local Accessibility (ACC) score."""
        la = self.metrics['LA']
        cp = self.metrics['CP']
        
        if any(m is None for m in [la, cp]):
            raise ValueError("All local accessibility metrics must be set")
        
        # Formula: (LA*CP)*10
        score = (la * cp) * 10
        self.scores['ACC'] = score
        return score

    def calculate_consequences(self):
        """Calculate Consequences (CON) score."""
        vi = self.metrics['VI']
        mi = self.metrics['MI']
        ci = self.metrics['CI']
        
        if any(m is None for m in [vi, mi, ci]):
            raise ValueError("All process consequence metrics must be set")
        
        # Enhanced formula with more weight on CI (process control)
        if self.adjustment_method == 'aggressive':
            # Give more weight to process control consequences
            score = ((vi + mi + ci * 4) / 6) * 10
        else:
            # Original formula
            score = ((vi + mi + ci * 3) / 5) * 10
            
        self.scores['CON'] = score
        return score

    def calculate_impact(self):
        """Calculate Impact (IMP) score."""
        # If using CVSS calculator, consider its impact calculation
        if self.use_cvss_calculator and hasattr(self.cvss_calculator, 'calculate_impact'):
            cvss_impact = self.cvss_calculator.calculate_impact()
            # We'll combine this with our industrial impact calculation later
        
        pi = self.metrics['PI']
        ri = self.metrics['RI']
        si = self.metrics['SI']
        cd = self.metrics['CD']
        
        if any(m is None for m in [pi, ri, si, cd]):
            raise ValueError("All impact metrics must be set")
        
        # Enhanced formula with more emphasis on safety and production
        if self.adjustment_method == 'aggressive':
            # More weight on safety and production
            score = (cd * 4 + pi * 3 + ri + si * 7) / 15 * 10
        else:
            # Original formula
            score = (cd * 5 * pi * 2 + ri + si * 6) / 14 * 10
            
        self.scores['IMP'] = score
        return score

    def calculate_adjusted_accessibility(self):
        """Calculate Adjusted Accessibility (ADJACC) score."""
        la = self.metrics['LA']
        
        if la is None:
            raise ValueError("Asset Access metric must be set")
        
        # Formula: LA*10
        self.scores['ADJACC'] = la * 10
        return la * 10

    def calculate_adjusted_criticality(self):
        """Calculate Adjusted Criticality (ADJIMP) score."""
        con = self.calculate_consequences()
        imp = self.calculate_impact()
        
        # Enhanced formula with stronger weighting for impact when using aggressive methods
        if self.adjustment_method == 'aggressive':
            # More weight on impact
            score = (con + (imp * 2.5)) / 3.5
        else:
            # Original formula
            score = (con + (imp * 2)) / 3
            
        self.scores['ADJIMP'] = score
        return score

    def calculate_modifier_impact(self):
        """
        Calculate the impact of IVSS modifiers on the CVSS base score.
        
        This helps quantify how much the industrial factors modify the score.
        """
        try:
            if not self.use_external_cvss and not self.use_cvss_calculator:
                return 0.0  # No modifiers if not using CVSS base
                
            # Industrial specific factors
            try:
                adj_imp = self.calculate_adjusted_criticality()
            except Exception:
                adj_imp = 5.0
                
            try:
                adj_acc = self.calculate_adjusted_accessibility()
            except Exception:
                adj_acc = 0.5
            
            # Standard CVSS score
            cvss_base = self.external_cvss_score
            
            # Calculate standard midpoint for comparison
            standard_midpoint = 5.0
            
            # Calculate modifier impact based on divergence from standard
            imp_factor = (adj_imp / 10.0) - 0.5  # -0.5 to +0.5 range
            acc_factor = (adj_acc / 10.0) - 0.5  # -0.5 to +0.5 range
            
            # Apply adjustment weights based on method
            if self.adjustment_method == 'aggressive':
                imp_weight = 0.8   # Increased from 0.6
                acc_weight = 0.6   # Increased from 0.4
                scale_factor = 3.0 # Increased from 2.0
            elif self.adjustment_method == 'conservative':
                imp_weight = 0.5   # Increased from 0.4
                acc_weight = 0.3   # Increased from 0.2
                scale_factor = 1.5 # Increased from 1.0
            else:  # 'balanced'
                imp_weight = 0.7   # Increased from 0.5
                acc_weight = 0.5   # Increased from 0.3
                scale_factor = 2.5 # Increased from 1.5
                        
            # Combined modifier impact
            modifier = (imp_factor * imp_weight + acc_factor * acc_weight) * scale_factor
            
            # Store the modifier impact
            self.scores['MODIFIER_IMPACT'] = modifier
            
            return modifier
        except Exception as e:
            import traceback
            print(f"ERROR in calculate_modifier_impact: {e}")
            print(traceback.format_exc())
            return 0.0  # Return safe default value

    def calculate_final_score(self):
        """Calculate final IVSS score based on all metrics."""
        try:
            # Case 1: Using CVSS base score with IVSS modifiers
            if self.use_external_cvss or self.use_cvss_calculator:
                cvss_base = self.external_cvss_score
                
                try:
                    modifier = self.calculate_modifier_impact()
                except Exception:
                    modifier = 0.0
                
                # Determine weight for the modifier based on adjustment method
                if self.adjustment_method == 'aggressive':
                    weight = 4.0  # Increased from 3.0
                elif self.adjustment_method == 'conservative':
                    weight = 1.5  # Increased from 1.0
                else:  # 'balanced'
                    weight = 3.0  # Increased from 2.0
                
                # Apply modifier to base score with appropriate weighting
                score = cvss_base + (modifier * weight)
                
                # Additional adjustment for edge and authentication bypass vulnerabilities
                # Check if BC (Consequence) is CONTROL (1.0) which indicates auth bypass
                if self.metrics.get('BC') == self.CONSEQUENCE_CONTROL:
                    # For authentication bypass, add another bonus
                    if self.adjustment_method == 'aggressive':
                        score += 0.8  # Significant bonus for auth bypass in ICS
                    else:
                        score += 0.5  # Moderate bonus for auth bypass
                
                # Check if CP (network segmentation) indicates boundary protection concerns
                if self.metrics.get('CP') == self.NETWORK_SEGMENTATION_PARTIAL or \
                   self.metrics.get('CP') == self.NETWORK_SEGMENTATION_DMZ_ONLY:
                    # For poor network segmentation, add another penalty
                    if self.adjustment_method == 'aggressive':
                        score += 0.9  # Significant penalty for segmentation issues
                    else:
                        score += 0.6  # Moderate penalty for segmentation issues
                
                # Ensure score is within valid range (0-10)
                score = max(0.0, min(10.0, score))
                
                # Store components for analysis
                self.scores['FINAL'] = score
                
                return score
                
            # Case 2: Full IVSS calculation
            else:
                try:
                    bs = self.calculate_base_severity_score()
                except Exception:
                    bs = 5.0
                    
                try:
                    adj_imp = self.calculate_adjusted_criticality()
                except Exception:
                    adj_imp = 5.0
                    
                try:
                    adj_acc = self.calculate_adjusted_accessibility()
                except Exception:
                    adj_acc = 0.5
                
                # Enhanced formulas for different adjustment methods
                if self.adjustment_method == 'aggressive':
                    score = (bs + adj_imp * 8 + adj_acc * 12) / 21  # More weight on impacts
                elif self.adjustment_method == 'conservative':
                    score = (bs * 2 + adj_imp * 3 + adj_acc * 6) / 11  # More weight on base score
                else:  # 'balanced'
                    score = (bs + adj_imp * 6 + adj_acc * 11) / 18  # Enhanced balanced formula
                
                # Additional bonus/penalty adjustments just like in the hybrid approach
                # Check if BC (Consequence) is CONTROL (1.0) which indicates auth bypass
                if self.metrics.get('BC') == self.CONSEQUENCE_CONTROL:
                    # For authentication bypass, add a bonus
                    if self.adjustment_method == 'aggressive':
                        score += 0.8  # Significant bonus for auth bypass in ICS
                    else:
                        score += 0.5  # Moderate bonus for auth bypass
                
                # Check if CP (network segmentation) indicates boundary protection concerns
                if self.metrics.get('CP') == self.NETWORK_SEGMENTATION_PARTIAL or \
                   self.metrics.get('CP') == self.NETWORK_SEGMENTATION_DMZ_ONLY:
                    # For poor network segmentation, add a penalty
                    if self.adjustment_method == 'aggressive':
                        score += 0.9  # Significant penalty for segmentation issues
                    else:
                        score += 0.6  # Moderate penalty for segmentation issues
                
                # Ensure score is within valid range (0-10)
                score = max(0.0, min(10.0, score))
                
                self.scores['FINAL'] = score
                return score
                
        except Exception as e:
            import traceback
            print(f"CRITICAL ERROR in calculate_final_score: {e}")
            print(traceback.format_exc())
            return 0.0

    def calculate_probability(self):
        """Calculate overall probability of exploitation with confidence influence."""
        # Use CVSS calculator's probability if available
        if self.use_cvss_calculator and hasattr(self.cvss_calculator, 'calculate_probability'):
            cvss_prob = self.cvss_calculator.calculate_probability()
            
            # Adjust CVSS probability with IVSS accessibility factors
            la = self.metrics.get('LA')
            cp = self.metrics.get('CP')
            
            # Get report confidence - crucial for accurate probabilities
            rc = self.metrics.get('RC', self.REPORT_CONFIDENCE_UNCONFIRMED) or 1
            
            if la is not None and cp is not None:
                # Combine CVSS probability with ICS environmental factors
                accessibility_factor = la * cp
                
                # Make RC have a direct, proportional impact on final probability
                confidence_factor = max(0.5, min(1.0, rc))  # Scale RC from 0.5-1.0
                
                # Adjust based on selected method
                if self.adjustment_method == 'aggressive':
                    # More weight to environmental factors
                    raw_prob = cvss_prob * 0.65 + accessibility_factor * 0.35
                    # Direct confidence scaling
                    final_prob = raw_prob * confidence_factor
                elif self.adjustment_method == 'conservative':
                    # Less weight to environmental factors
                    raw_prob = cvss_prob * 0.9 + accessibility_factor * 0.1
                    # Milder confidence scaling 
                    final_prob = raw_prob * (0.8 + (0.2 * confidence_factor))
                else:  # 'balanced'
                    # Equal weighting
                    raw_prob = cvss_prob * 0.75 + accessibility_factor * 0.25
                    # Moderate confidence scaling
                    final_prob = raw_prob * (0.7 + (0.3 * confidence_factor))
                
                # Ensure probability is in valid range
                return min(1.0, max(0.01, final_prob))
            else:
                # Return CVSS probability scaled by confidence if IVSS factors aren't set
                return min(1.0, max(0.01, cvss_prob * max(0.5, rc)))
        
        # If not using CVSS calculator, proceed with standard IVSS calculation
        
        # Base exploitability factors
        ec = self.metrics['EC']
        ex = self.metrics['EX']
        au = self.metrics['AU']
        ui = self.metrics['UI']
        av = self.metrics['AV']
        
        # Local environment factors affecting accessibility
        la = self.metrics['LA']
        cp = self.metrics['CP']
        
        # Report confidence - direct scaling factor
        rc = self.metrics['RC']
        
        # Check if required metrics are set
        required_metrics = ['EC', 'EX', 'AU', 'UI', 'AV', 'LA', 'CP', 'RC']
        if any(self.metrics[m] is None for m in required_metrics):
            # Return default probability if metrics aren't fully set
            return 0.5
        
        # Base exploitability core factors (same as BEX calculation but without scaling to 10)
        base_exploit_prob = (ec + ex + au + ui) / 4
        
        # Threat vector and local environment factors
        accessibility_prob = av * la * cp
        
        # Apply confidence scaling with method-specific strength
        if self.adjustment_method == 'aggressive':
            # More weight on environmental factors
            raw_prob = (base_exploit_prob * 0.55 + accessibility_prob * 0.45)
            # Direct scaling by RC
            probability = raw_prob * rc
        elif self.adjustment_method == 'conservative':
            # Less weight on environmental factors
            raw_prob = (base_exploit_prob * 0.7 + accessibility_prob * 0.3)
            # Milder RC impact
            probability = raw_prob * (0.8 + (0.2 * rc))
        else:  # 'balanced'
            # Default weights
            raw_prob = (base_exploit_prob * 0.6 + accessibility_prob * 0.4)
            # Moderate RC impact
            probability = raw_prob * (0.7 + (0.3 * rc))
        
        # Ensure in valid range
        return min(1.0, max(0.01, probability))

    def _calculate_industrial_impact(self):
        """
        Calculate industrial-specific impact for combining with CVSS impact.
        This is a helper method to calculate impact from ICS-specific metrics.
        """
        # Process consequences
        vi = self.metrics.get('VI')
        mi = self.metrics.get('MI')
        ci = self.metrics.get('CI')
        
        # Impact metrics
        pi = self.metrics.get('PI')
        ri = self.metrics.get('RI')
        si = self.metrics.get('SI')
        cd = self.metrics.get('CD')
        
        # If any metric is missing, return a moderate impact
        if any(m is None for m in [vi, mi, ci, pi, ri, si, cd]):
            return 5.0
        
        # Calculate process consequences component with increased weight on CI
        process_impact = ((vi + mi + ci * 3.5) / 5.5) * 10
        
        # Calculate impact metrics component with increased emphasis on safety and production
        system_impact = (pi * 2.5 + ri + si * 3.5 + cd) / 8 * 10
        
        # Combined impact with more weight on system impact
        return (process_impact + system_impact * 2) / 3

    def calculate_impact(self):
        """Calculate Impact for risk assessment."""
        # If using CVSS calculator, get its impact and combine with industrial factors
        if self.use_cvss_calculator and hasattr(self.cvss_calculator, 'calculate_impact'):
            cvss_impact = self.cvss_calculator.calculate_impact()
            
            # Get industrial impact factors
            industrial_impact = self._calculate_industrial_impact() 
            
            if self.adjustment_method == 'aggressive':
                # More weight to industrial factors
                impact = (cvss_impact * 0.3 + industrial_impact * 0.7)
            elif self.adjustment_method == 'conservative':
                # Less weight to industrial factors
                impact = (cvss_impact * 0.6 + industrial_impact * 0.4)
            else:  # 'balanced'
                # Equal weighting
                impact = (cvss_impact * 0.4 + industrial_impact * 0.6)
            
            return impact
        
        # Process consequences
        vi = self.metrics['VI']
        mi = self.metrics['MI']
        ci = self.metrics['CI']
        
        # Impact metrics
        pi = self.metrics['PI']
        ri = self.metrics['RI']
        si = self.metrics['SI']
        cd = self.metrics['CD']
        
        # Check if required metrics are set
        required_metrics = ['VI', 'MI', 'CI', 'PI', 'RI', 'SI', 'CD']
        if any(self.metrics[m] is None for m in required_metrics):
            # Return default impact if metrics aren't fully set
            return 5.0
            
        # Calculate process consequences with enhanced CI weight for critical processes
        if self.adjustment_method == 'aggressive':
            con = ((vi + mi + ci * 4) / 6) * 10  # More weight on process control
        else:
            con = ((vi + mi + ci * 3) / 5) * 10  # Original formula
        
        # Calculate impact with enhanced safety and production impact weights
        if self.adjustment_method == 'aggressive':
            # More weight on safety and production
            imp = (cd * 4 + pi * 3 + ri + si * 7) / 15 * 10
        else:
            # Original formula
            imp = (cd * 5 * pi * 2 + ri + si * 6) / 14 * 10
        
        # Combine for final impact with method-specific weights
        if self.adjustment_method == 'aggressive':
            adj_imp = (con + (imp * 2.5)) / 3.5  # More weight on system impacts
        else:
            adj_imp = (con + (imp * 2)) / 3  # Original formula
            
        return adj_imp