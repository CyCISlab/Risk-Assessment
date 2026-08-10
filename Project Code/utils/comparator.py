"""
Comparator Tool

Provides tools for comparing CVSS, IVSS, and CVSS+IVSS hybrid vulnerability scoring systems.
"""

import json
import sys
import os
import datetime
from typing import Dict
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scoring.cvss_calculator import CVSSv4Calculator
from scoring.ivss_calculator import IVSSCalculator


class VulnerabilityComparator:
    
    def __init__(self):
        self.cvss_calculator = CVSSv4Calculator()
        self.ivss_calculator = IVSSCalculator()
        self.hybrid_calculator = IVSSCalculator()
        self.results = []
        self.metadata = {}
        
        # Set default scoring approach
        self.scoring_approach = "comprehensive"  # "cvss_only", "ivss_only", "hybrid_only", or "comprehensive"
        self.ivss_adjustment_method = "balanced"  # "balanced", "aggressive", or "conservative"
    
    def set_scoring_approach(self, approach, adjustment_method=None):
        """
        Set the scoring approach for comparing vulnerabilities.
        
        Args:
            approach: String indicating which approach to use
                "cvss_only" - Only calculate CVSS scores
                "ivss_only" - Only calculate standalone IVSS scores
                "hybrid_only" - Only calculate CVSS+IVSS hybrid scores
                "comprehensive" - Calculate all three for comparison
            adjustment_method: For hybrid approach, the adjustment method
                "balanced", "aggressive", or "conservative"
        """
        valid_approaches = ["cvss_only", "ivss_only", "hybrid_only", "comprehensive"]
        if approach not in valid_approaches:
            raise ValueError(f"Approach must be one of: {valid_approaches}")
        
        self.scoring_approach = approach
        
        if adjustment_method:
            valid_methods = ["balanced", "aggressive", "conservative"]
            if adjustment_method not in valid_methods:
                raise ValueError(f"Adjustment method must be one of: {valid_methods}")
            self.ivss_adjustment_method = adjustment_method
            
        return self
    
    def assess_vulnerability(self, vuln_id, description, cvss_params, ivss_params):
        """
        Assess vulnerability using selected methodologies.
        
        Parameters:
        - vuln_id: ID of vulnerability (e.g., CVE number)
        - description: Description of vulnerability
        - cvss_params: Dictionary of CVSS parameters or initialized CVSSv4Calculator
        - ivss_params: Dictionary of IVSS parameters or initialized IVSSCalculator
        
        Returns:
        - Dictionary with assessment results
        """
        result = {
            'id': vuln_id,
            'description': description,
            'scoring_approach': self.scoring_approach,
        }
        
        # Initialize empty containers for comparison data
        comparison = {}
        
        # 1. Calculate CVSS score if needed
        if self.scoring_approach in ["cvss_only", "hybrid_only", "comprehensive"]:
            cvss_data = self._calculate_cvss(cvss_params)
            result['cvss'] = cvss_data
        
        # 2. Calculate standalone IVSS if needed
        if self.scoring_approach in ["ivss_only", "comprehensive"]:
            ivss_data = self._calculate_standalone_ivss(ivss_params)
            result['standalone_ivss'] = ivss_data
            
            # If we have both CVSS and IVSS, calculate comparison
            if 'cvss' in result:
                comparison['cvss_ivss'] = self._calculate_comparison(
                    result['cvss']['score'], 
                    result['standalone_ivss']['score'],
                    result['cvss']['probability'],
                    result['standalone_ivss']['probability'],
                    result['cvss']['impact'],
                    result['standalone_ivss']['impact'],
                    result['cvss']['risk'],
                    result['standalone_ivss']['risk']
                )
        
        # 3. Calculate hybrid CVSS+IVSS if needed
        if self.scoring_approach in ["hybrid_only", "comprehensive"]:
            # Need to ensure CVSS is calculated first
            if 'cvss' not in result:
                cvss_data = self._calculate_cvss(cvss_params)
                result['cvss'] = cvss_data
                
            hybrid_data = self._calculate_hybrid_ivss(ivss_params)
            result['hybrid_ivss'] = hybrid_data
            
            # Calculate comparison between CVSS and hybrid
            comparison['cvss_hybrid'] = self._calculate_comparison(
                result['cvss']['score'], 
                result['hybrid_ivss']['score'],
                result['cvss']['probability'],
                result['hybrid_ivss']['probability'],
                result['cvss']['impact'],
                result['hybrid_ivss']['impact'],
                result['cvss']['risk'],
                result['hybrid_ivss']['risk']
            )
            
            # If we have all three, calculate comparison between standalone IVSS and hybrid
            if 'standalone_ivss' in result:
                comparison['ivss_hybrid'] = self._calculate_comparison(
                    result['standalone_ivss']['score'], 
                    result['hybrid_ivss']['score'],
                    result['standalone_ivss']['probability'],
                    result['hybrid_ivss']['probability'],
                    result['standalone_ivss']['impact'],
                    result['hybrid_ivss']['impact'],
                    result['standalone_ivss']['risk'],
                    result['hybrid_ivss']['risk']
                )
        
        # Add comparison data to result
        if comparison:
            result['comparison'] = comparison
            
        self.results.append(result)
        return result
    
    def _calculate_cvss(self, cvss_params):
        """Calculate CVSS scores"""
        # Handle different types of inputs for CVSS
        if isinstance(cvss_params, CVSSv4Calculator):
            # Use the provided calculator directly
            self.cvss_calculator = cvss_params
        else:
            # Handle dictionary of parameters
            self.cvss_calculator = CVSSv4Calculator()
            if 'base_metrics' in cvss_params:
                self.cvss_calculator.set_base_metrics(**cvss_params.get('base_metrics', {}))
            if 'threat_metrics' in cvss_params:
                self.cvss_calculator.set_threat_metrics(**cvss_params.get('threat_metrics', {}))
            if 'environmental_metrics' in cvss_params:
                self.cvss_calculator.set_environmental_metrics(**cvss_params.get('environmental_metrics', {}))
            
        # Calculate CVSS score
        cvss_score = self.cvss_calculator.calculate_base_score()
        cvss_vector = self.cvss_calculator.to_vector_string()
        # Calculate additional CVSS metrics
        cvss_probability = self.cvss_calculator.calculate_probability()
        cvss_impact = self.cvss_calculator.calculate_impact()
        cvss_risk = self.cvss_calculator.calculate_risk()
        
        return {
            "score": cvss_score,
            "vector": cvss_vector,
            "probability": cvss_probability,
            "impact": cvss_impact,
            "risk": cvss_risk
        }
    
    def _calculate_standalone_ivss(self, ivss_params):
        """Calculate IVSS scores using the standalone approach"""
        # Handle different types of inputs for IVSS
        if isinstance(ivss_params, IVSSCalculator):
            # Use the provided calculator directly
            self.ivss_calculator = ivss_params
        else:
            # Handle dictionary of parameters
            self.ivss_calculator = IVSSCalculator()
            # Calculate IVSS independently
            if 'base_metrics' in ivss_params:
                self.ivss_calculator.set_base_metrics(**ivss_params.get('base_metrics', {}))
            
            # Set IVSS-specific parameters
            if 'local_environment' in ivss_params:
                self.ivss_calculator.set_local_environment_metrics(**ivss_params.get('local_environment', {}))
            if 'process_consequences' in ivss_params:
                self.ivss_calculator.set_process_consequence_metrics(**ivss_params.get('process_consequences', {}))
            if 'impact_metrics' in ivss_params:
                self.ivss_calculator.set_impact_metrics(**ivss_params.get('impact_metrics', {}))
        
        # Calculate IVSS score
        ivss_score = self.ivss_calculator.calculate_final_score()
        ivss_vector = self.ivss_calculator.to_vector_string()
        # Calculate additional IVSS metrics
        ivss_probability = self.ivss_calculator.calculate_probability()
        ivss_impact = self.ivss_calculator.calculate_impact()
        ivss_risk = self.ivss_calculator.calculate_risk()
        
        return {
            "score": ivss_score,
            "vector": ivss_vector,
            "probability": ivss_probability,
            "impact": ivss_impact,
            "risk": ivss_risk,
            "detailed_scores": self.ivss_calculator.scores.copy(),
            "modifier_impact": 0  # No modifier in standalone mode
        }
    
    def _calculate_hybrid_ivss(self, ivss_params):
        """Calculate IVSS scores using the hybrid CVSS+IVSS approach"""
        # Create a new IVSS calculator for the hybrid approach
        self.hybrid_calculator = IVSSCalculator()
        
        # Set the CVSS calculator
        self.hybrid_calculator.set_cvss_calculator(self.cvss_calculator)
        
        # Set the adjustment method
        self.hybrid_calculator.set_adjustment_method(self.ivss_adjustment_method)
        
        # Handle different types of inputs for IVSS params
        if isinstance(ivss_params, IVSSCalculator):
            # Copy environmental metrics from provided calculator
            if hasattr(ivss_params, 'metrics') and hasattr(ivss_params.metrics, 'LA'):
                self.hybrid_calculator.set_local_environment_metrics(
                    la=ivss_params.metrics.get('LA'),
                    cp=ivss_params.metrics.get('CP')
                )
            
            if hasattr(ivss_params, 'metrics') and hasattr(ivss_params.metrics, 'VI'):
                self.hybrid_calculator.set_process_consequence_metrics(
                    vi=ivss_params.metrics.get('VI'),
                    mi=ivss_params.metrics.get('MI'),
                    ci=ivss_params.metrics.get('CI')
                )
            
            if hasattr(ivss_params, 'metrics') and hasattr(ivss_params.metrics, 'PI'):
                self.hybrid_calculator.set_impact_metrics(
                    pi=ivss_params.metrics.get('PI'),
                    ri=ivss_params.metrics.get('RI'),
                    si=ivss_params.metrics.get('SI'),
                    cd=ivss_params.metrics.get('CD')
                )
        else:
            # Set IVSS-specific parameters from dictionary
            if 'local_environment' in ivss_params:
                self.hybrid_calculator.set_local_environment_metrics(**ivss_params.get('local_environment', {}))
            if 'process_consequences' in ivss_params:
                self.hybrid_calculator.set_process_consequence_metrics(**ivss_params.get('process_consequences', {}))
            if 'impact_metrics' in ivss_params:
                self.hybrid_calculator.set_impact_metrics(**ivss_params.get('impact_metrics', {}))
        
        # Calculate IVSS score
        ivss_score = self.hybrid_calculator.calculate_final_score()
        ivss_vector = self.hybrid_calculator.to_vector_string()
        # Calculate additional IVSS metrics
        ivss_probability = self.hybrid_calculator.calculate_probability()
        ivss_impact = self.hybrid_calculator.calculate_impact()
        ivss_risk = self.hybrid_calculator.calculate_risk()
        
        # Get the modifier impact (how much IVSS changed the CVSS score)
        modifier_impact = self.hybrid_calculator.scores.get('MODIFIER_IMPACT', 0)
        
        return {
            "score": ivss_score,
            "vector": ivss_vector,
            "probability": ivss_probability,
            "impact": ivss_impact,
            "risk": ivss_risk,
            "detailed_scores": self.hybrid_calculator.scores.copy(),
            "modifier_impact": modifier_impact,
            "adjustment_method": self.ivss_adjustment_method
        }
    
    def _calculate_comparison(self, score1, score2, prob1, prob2, impact1, impact2, risk1, risk2):
        """Calculate comparison metrics between two scoring approaches"""
        return {
            "absolute_difference": abs(score1 - score2),
            "percentage_difference": abs(score1 - score2) / max(score1, score2) * 100 if max(score1, score2) > 0 else 0,
            "severity_shift": self._determine_severity_shift(score1, score2),
            "probability_difference": abs(prob1 - prob2),
            "impact_difference": abs(impact1 - impact2),
            "risk_difference": abs(risk1 - risk2)
        }
    
    def _determine_severity_shift(self, score1, score2):
        """
        Determine if severity category shifts between two scores.
        
        CVSS v4.0 severity ratings:
        - 0.0-0.1: None
        - 0.1-3.9: Low
        - 4.0-6.9: Medium
        - 7.0-8.9: High
        - 9.0-10.0: Critical
        """
        category1 = self._get_severity_category(score1)
        category2 = self._get_severity_category(score2)
        
        if category1 == category2:
            return "No change"
        elif self._category_value(category1) < self._category_value(category2):
            return f"Increased ({category1} → {category2})"
        else:
            return f"Decreased ({category1} → {category2})"
    
    def _get_severity_category(self, score):
        """Get severity category based on score."""
        if score < 0.1:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
    
    def _category_value(self, category):
        """Convert severity category to numerical value for comparison."""
        values = {
            "None": 0,
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }
        return values.get(category, 0)
    
    def export_key_statistics_to_json(self, filename=None):
        """
        Export key statistics from vulnerability comparison analysis in JSON format.
        
        Args:
            filename: Optional filename to save JSON. If None, returns JSON string.
        
        Returns:
            JSON string if filename is None, otherwise returns True if successful
        """
        # First, get the full analysis
        analysis = self.analyse_results()
        
        if "error" in analysis:
            key_stats = {"error": analysis["error"]}
            return json.dumps(key_stats) if filename is None else False
        
        # Extract key statistics based on the scoring approach
        approach = analysis.get("approach", "comprehensive")
        
        # Build key statistics dictionary
        key_stats = {
            "metadata": {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scoring_approach": approach,
                "total_vulnerabilities": analysis.get("total_vulnerabilities", 0)
            }
        }
        
        # Add approach-specific statistics
        if approach == "comprehensive":
            # Add average scores
            if "average_scores" in analysis:
                key_stats["average_scores"] = analysis["average_scores"]
            
            # Add average differences
            if "average_differences" in analysis:
                key_stats["average_differences"] = analysis["average_differences"]
            
            # Add severity shifts
            if "severity_shifts" in analysis:
                key_stats["severity_shifts"] = analysis["severity_shifts"]
                
            # Add correlations
            correlations = self.calculate_pearson_correlation()
            if correlations and "error" not in correlations:
                key_stats["correlations"] = correlations
        
        elif approach == "hybrid_only":
            # Add key hybrid analysis stats
            if "average_scores" in analysis:
                key_stats["average_scores"] = analysis["average_scores"]
            
            # Add adjustment method
            key_stats["adjustment_method"] = analysis.get("adjustment_method", "balanced")
            
            # Add severity shifts
            if "severity_shifts" in analysis:
                key_stats["severity_shifts"] = analysis["severity_shifts"]
        
        else:  # cvss_only or ivss_only
            # Add basic statistics
            key_stats["average_score"] = analysis.get("average_score", 0)
            
            # Add severity distribution if available
            if "severity_distribution" in analysis:
                key_stats["severity_distribution"] = analysis["severity_distribution"]
        
        # Add list of analyzed vulnerabilities with their scores
        vuln_list = []
        for result in self.results:
            vuln_scores = {"id": result["id"]}
            
            # Add scores based on what's available
            if "cvss" in result and "score" in result["cvss"]:
                vuln_scores["cvss_score"] = result["cvss"]["score"]
            
            if "standalone_ivss" in result and "score" in result["standalone_ivss"]:
                vuln_scores["ivss_score"] = result["standalone_ivss"]["score"]
            elif "ivss" in result and "score" in result["ivss"]:
                vuln_scores["ivss_score"] = result["ivss"]["score"]
                
            if "hybrid_ivss" in result and "score" in result["hybrid_ivss"]:
                vuln_scores["hybrid_score"] = result["hybrid_ivss"]["score"]
            elif "hybrid" in result and "score" in result["hybrid"]:
                vuln_scores["hybrid_score"] = result["hybrid"]["score"]
                
            vuln_list.append(vuln_scores)
        
        key_stats["vulnerabilities"] = vuln_list
        
        # Convert to JSON
        json_data = json.dumps(key_stats, indent=2)
        
        # Save to file if requested
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(json_data)
                return True
            except Exception as e:
                print(f"Error saving JSON stats: {e}")
                return False
        
        # Otherwise, return the JSON string
        return json_data
    def analyse_results(self):
        """
        Analyse comparison results and generate statistics.
        
        Returns:
        - Dictionary with analysis results
        """
        if not self.results:
            return {"error": "No vulnerabilities assessed yet"}
        
        # Determine which approach was used
        approach = self.results[0].get('scoring_approach', 'comprehensive')
        
        if approach == 'comprehensive':
            return self._analyse_comprehensive_results()
        elif approach == 'hybrid_only':
            return self._analyse_hybrid_results()
        elif approach == 'ivss_only':
            return self._analyse_ivss_results()
        else:  # 'cvss_only'
            return self._analyse_cvss_results()
    
    def _analyse_cvss_results(self):
        """Analyze results from CVSS-only approach"""
        # Calculate basic statistics for CVSS scores
        cvss_scores = [r['cvss']['score'] for r in self.results]
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        
        # Count severity categories
        severity_counts = {}
        for result in self.results:
            category = self._get_severity_category(result['cvss']['score'])
            severity_counts[category] = severity_counts.get(category, 0) + 1
        
        # Find highest and lowest scored vulnerabilities
        sorted_by_score = sorted(self.results, key=lambda r: r['cvss']['score'], reverse=True)
        highest_scores = sorted_by_score[:3] if len(sorted_by_score) >= 3 else sorted_by_score
        lowest_scores = sorted_by_score[-3:] if len(sorted_by_score) >= 3 else sorted_by_score
        
        return {
            "approach": "cvss_only",
            "total_vulnerabilities": len(self.results),
            "average_score": avg_cvss,
            "severity_distribution": severity_counts,
            "highest_scores": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "cvss_score": r['cvss']['score'],
                    "severity": self._get_severity_category(r['cvss']['score'])
                }
                for r in highest_scores
            ],
            "lowest_scores": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "cvss_score": r['cvss']['score'],
                    "severity": self._get_severity_category(r['cvss']['score'])
                }
                for r in lowest_scores
            ]
        }
    
    def _analyse_ivss_results(self):
        """Analyze results from IVSS-only approach"""
        # Similar to CVSS but for IVSS
        ivss_scores = [r['standalone_ivss']['score'] for r in self.results]
        avg_ivss = sum(ivss_scores) / len(ivss_scores)
        
        # Count severity categories
        severity_counts = {}
        for result in self.results:
            category = self._get_severity_category(result['standalone_ivss']['score'])
            severity_counts[category] = severity_counts.get(category, 0) + 1
        
        # Find highest and lowest scored vulnerabilities
        sorted_by_score = sorted(self.results, key=lambda r: r['standalone_ivss']['score'], reverse=True)
        highest_scores = sorted_by_score[:3] if len(sorted_by_score) >= 3 else sorted_by_score
        lowest_scores = sorted_by_score[-3:] if len(sorted_by_score) >= 3 else sorted_by_score
        
        return {
            "approach": "ivss_only",
            "total_vulnerabilities": len(self.results),
            "average_score": avg_ivss,
            "severity_distribution": severity_counts,
            "highest_scores": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "ivss_score": r['standalone_ivss']['score'],
                    "severity": self._get_severity_category(r['standalone_ivss']['score'])
                }
                for r in highest_scores
            ],
            "lowest_scores": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "ivss_score": r['standalone_ivss']['score'],
                    "severity": self._get_severity_category(r['standalone_ivss']['score'])
                }
                for r in lowest_scores
            ]
        }
    
    def _analyse_hybrid_results(self):
        """Analyze results from hybrid CVSS+IVSS approach"""
        # Basic statistics for hybrid approach
        cvss_scores = [r['cvss']['score'] for r in self.results]
        hybrid_scores = [r['hybrid_ivss']['score'] for r in self.results]
        
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        avg_hybrid = sum(hybrid_scores) / len(hybrid_scores)
        
        # Count severity shifts
        severity_shifts = {}
        for result in self.results:
            shift = result['comparison']['cvss_hybrid']['severity_shift']
            severity_shifts[shift] = severity_shifts.get(shift, 0) + 1
        
        # Get average modifier impact
        modifier_impacts = [r['hybrid_ivss'].get('modifier_impact', 0) for r in self.results]
        avg_modifier = sum(modifier_impacts) / len(modifier_impacts) if modifier_impacts else 0
        
        # Find largest differences
        sorted_by_diff = sorted(self.results, 
                               key=lambda r: r['comparison']['cvss_hybrid']['absolute_difference'], 
                               reverse=True)
        largest_differences = sorted_by_diff[:3] if len(sorted_by_diff) >= 3 else sorted_by_diff
        
        # Sort by modifier impact
        sorted_by_modifier = sorted(self.results, 
                                   key=lambda r: abs(r['hybrid_ivss'].get('modifier_impact', 0)), 
                                   reverse=True)
        largest_modifiers = sorted_by_modifier[:3] if len(sorted_by_modifier) >= 3 else sorted_by_modifier
        
        return {
            "approach": "hybrid_only",
            "total_vulnerabilities": len(self.results),
            "adjustment_method": self.ivss_adjustment_method,
            "average_scores": {
                "cvss": avg_cvss,
                "hybrid": avg_hybrid,
                "difference": abs(avg_cvss - avg_hybrid)
            },
            "severity_shifts": severity_shifts,
            "modifier_impact": {
                "average": avg_modifier,
                "largest_modifiers": [
                    {
                        "id": r['id'],
                        "description": r['description'],
                        "cvss_score": r['cvss']['score'],
                        "hybrid_score": r['hybrid_ivss']['score'],
                        "modifier_impact": r['hybrid_ivss'].get('modifier_impact', 0)
                    }
                    for r in largest_modifiers
                ]
            },
            "largest_differences": [
                {
                    "id": r['id'],
                    "description": r['description'],
                    "cvss_score": r['cvss']['score'],
                    "hybrid_score": r['hybrid_ivss']['score'],
                    "difference": r['comparison']['cvss_hybrid']['absolute_difference'],
                    "severity_shift": r['comparison']['cvss_hybrid']['severity_shift']
                }
                for r in largest_differences
            ]
        }
    
    def _analyse_comprehensive_results(self):
        """Analyze results from comprehensive approach (all three methods)"""
        # Collect scores for all three approaches with fallbacks for different data formats
        all_cvss_scores = []
        all_ivss_scores = []
        all_hybrid_scores = []
        
        for r in self.results:
            # Get CVSS scores
            if 'cvss' in r and 'score' in r['cvss']:
                all_cvss_scores.append(r['cvss']['score'])
            
            # Get IVSS scores (try standalone_ivss first, then fall back to legacy ivss)
            if 'standalone_ivss' in r and 'score' in r['standalone_ivss']:
                all_ivss_scores.append(r['standalone_ivss']['score'])
            elif 'ivss' in r and 'score' in r['ivss']:
                all_ivss_scores.append(r['ivss']['score'])
            
            # Get Hybrid scores (try hybrid_ivss first, then fall back to legacy hybrid)
            if 'hybrid_ivss' in r and 'score' in r['hybrid_ivss']:
                all_hybrid_scores.append(r['hybrid_ivss']['score'])
            elif 'hybrid' in r and 'score' in r['hybrid']:
                all_hybrid_scores.append(r['hybrid']['score'])
        
        # Skip analysis if we don't have enough data
        if not all_cvss_scores or not all_ivss_scores:
            return {"error": "Insufficient data for comprehensive analysis"}
        
        # Calculate average scores
        avg_cvss = sum(all_cvss_scores) / len(all_cvss_scores)
        avg_ivss = sum(all_ivss_scores) / len(all_ivss_scores)
        avg_hybrid = sum(all_hybrid_scores) / len(all_hybrid_scores) if all_hybrid_scores else 0
        
        # Count severity shifts for each comparison
        shifts_cvss_ivss = {}
        shifts_cvss_hybrid = {}
        shifts_ivss_hybrid = {}
        
        for result in self.results:
            # We need to have CVSS scores
            if 'cvss' not in result or 'score' not in result['cvss']:
                continue
                
            cvss_score = result['cvss']['score']
            
            # Get standalone IVSS score if available
            ivss_score = None
            if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                ivss_score = result['standalone_ivss']['score']
            elif 'ivss' in result and 'score' in result['ivss']:
                ivss_score = result['ivss']['score']
            
            # Get hybrid score if available
            hybrid_score = None
            if 'hybrid_ivss' in result and 'score' in result['hybrid_ivss']:
                hybrid_score = result['hybrid_ivss']['score']
            elif 'hybrid' in result and 'score' in result['hybrid']:
                hybrid_score = result['hybrid']['score']
            
            # Extract severity shifts from comparisons if available
            if 'comparison' in result:
                # CVSS vs IVSS shift
                if 'cvss_ivss' in result['comparison']:
                    shift_cvss_ivss = result['comparison']['cvss_ivss']['severity_shift']
                    shifts_cvss_ivss[shift_cvss_ivss] = shifts_cvss_ivss.get(shift_cvss_ivss, 0) + 1
                
                # CVSS vs Hybrid shift
                if 'cvss_hybrid' in result['comparison']:
                    shift_cvss_hybrid = result['comparison']['cvss_hybrid']['severity_shift']
                    shifts_cvss_hybrid[shift_cvss_hybrid] = shifts_cvss_hybrid.get(shift_cvss_hybrid, 0) + 1
                
                # IVSS vs Hybrid shift
                if 'ivss_hybrid' in result['comparison']:
                    shift_ivss_hybrid = result['comparison']['ivss_hybrid']['severity_shift']
                    shifts_ivss_hybrid[shift_ivss_hybrid] = shifts_ivss_hybrid.get(shift_ivss_hybrid, 0) + 1
            # Calculate shifts directly if not available in comparison
            else:
                # Only calculate if we have both scores
                if ivss_score is not None:
                    shift_cvss_ivss = self._determine_severity_shift(cvss_score, ivss_score)
                    shifts_cvss_ivss[shift_cvss_ivss] = shifts_cvss_ivss.get(shift_cvss_ivss, 0) + 1
                
                if hybrid_score is not None:
                    shift_cvss_hybrid = self._determine_severity_shift(cvss_score, hybrid_score)
                    shifts_cvss_hybrid[shift_cvss_hybrid] = shifts_cvss_hybrid.get(shift_cvss_hybrid, 0) + 1
                    
                    if ivss_score is not None:
                        shift_ivss_hybrid = self._determine_severity_shift(ivss_score, hybrid_score)
                        shifts_ivss_hybrid[shift_ivss_hybrid] = shifts_ivss_hybrid.get(shift_ivss_hybrid, 0) + 1
        
        # Calculate average differences
        avg_diff_cvss_ivss = sum(abs(c - i) for c, i in zip(all_cvss_scores, all_ivss_scores)) / len(all_cvss_scores)
        
        avg_diff_cvss_hybrid = 0
        if all_hybrid_scores:
            avg_diff_cvss_hybrid = sum(abs(c - h) for c, h in zip(all_cvss_scores, all_hybrid_scores)) / len(all_cvss_scores)
        
        avg_diff_ivss_hybrid = 0
        if all_hybrid_scores:
            avg_diff_ivss_hybrid = sum(abs(i - h) for i, h in zip(all_ivss_scores, all_hybrid_scores)) / len(all_ivss_scores)
        
        # Find vulnerabilities with largest differences
        # For CVSS vs IVSS
        largest_diff_cvss_ivss = []
        for i, result in enumerate(self.results):
            if i >= len(all_cvss_scores) or i >= len(all_ivss_scores):
                continue
                
            cvss_score = all_cvss_scores[i]
            ivss_score = all_ivss_scores[i]
            
            difference = abs(cvss_score - ivss_score)
            severity_shift = self._determine_severity_shift(cvss_score, ivss_score)
            
            largest_diff_cvss_ivss.append({
                "id": result['id'],
                "description": result.get('description', ''),
                "cvss_score": cvss_score,
                "standalone_score": ivss_score,
                "difference": difference,
                "severity_shift": severity_shift
            })
        
        # Sort by difference
        largest_diff_cvss_ivss.sort(key=lambda x: x['difference'], reverse=True)
        
        # For CVSS vs Hybrid
        largest_diff_cvss_hybrid = []
        if all_hybrid_scores:
            for i, result in enumerate(self.results):
                if i >= len(all_cvss_scores) or i >= len(all_hybrid_scores):
                    continue
                    
                cvss_score = all_cvss_scores[i]
                hybrid_score = all_hybrid_scores[i]
                
                difference = abs(cvss_score - hybrid_score)
                severity_shift = self._determine_severity_shift(cvss_score, hybrid_score)
                
                largest_diff_cvss_hybrid.append({
                    "id": result['id'],
                    "description": result.get('description', ''),
                    "cvss_score": cvss_score,
                    "hybrid_score": hybrid_score,
                    "difference": difference,
                    "severity_shift": severity_shift
                })
            
            # Sort by difference
            largest_diff_cvss_hybrid.sort(key=lambda x: x['difference'], reverse=True)
        
        # For IVSS vs Hybrid
        largest_diff_ivss_hybrid = []
        if all_hybrid_scores:
            for i, result in enumerate(self.results):
                if i >= len(all_ivss_scores) or i >= len(all_hybrid_scores):
                    continue
                    
                ivss_score = all_ivss_scores[i]
                hybrid_score = all_hybrid_scores[i]
                
                difference = abs(ivss_score - hybrid_score)
                severity_shift = self._determine_severity_shift(ivss_score, hybrid_score)
                
                largest_diff_ivss_hybrid.append({
                    "id": result['id'],
                    "description": result.get('description', ''),
                    "standalone_score": ivss_score,
                    "hybrid_score": hybrid_score,
                    "difference": difference,
                    "severity_shift": severity_shift
                })
            
            # Sort by difference
            largest_diff_ivss_hybrid.sort(key=lambda x: x['difference'], reverse=True)
        
        # Get average modifier impact
        modifier_impacts = []
        for r in self.results:
            if 'hybrid_ivss' in r and 'modifier_impact' in r['hybrid_ivss']:
                modifier_impacts.append(r['hybrid_ivss'].get('modifier_impact', 0))
            elif 'hybrid' in r and 'modifier_impact' in r['hybrid']:
                modifier_impacts.append(r['hybrid'].get('modifier_impact', 0))
        
        avg_modifier = sum(modifier_impacts) / len(modifier_impacts) if modifier_impacts else 0
        
        # Build the comprehensive analysis
        return {
            "approach": "comprehensive",
            "total_vulnerabilities": len(self.results),
            "adjustment_method": self.ivss_adjustment_method,
            "average_scores": {
                "cvss": avg_cvss,
                "standalone_ivss": avg_ivss,
                "hybrid_ivss": avg_hybrid
            },
            "average_differences": {
                "cvss_to_standalone": avg_diff_cvss_ivss,
                "cvss_to_hybrid": avg_diff_cvss_hybrid,
                "standalone_to_hybrid": avg_diff_ivss_hybrid
            },
            "severity_shifts": {
                "cvss_to_standalone": shifts_cvss_ivss,
                "cvss_to_hybrid": shifts_cvss_hybrid,
                "standalone_to_hybrid": shifts_ivss_hybrid
            },
            "largest_differences": {
                "cvss_to_standalone": largest_diff_cvss_ivss[:3] if len(largest_diff_cvss_ivss) >= 3 else largest_diff_cvss_ivss,
                "cvss_to_hybrid": largest_diff_cvss_hybrid[:3] if len(largest_diff_cvss_hybrid) >= 3 else largest_diff_cvss_hybrid,
                "standalone_to_hybrid": largest_diff_ivss_hybrid[:3] if len(largest_diff_ivss_hybrid) >= 3 else largest_diff_ivss_hybrid
            },
            "modifier_impact": {
                "average": avg_modifier
            }
        }
    
    def export_results_to_json(self, filename):
        """
        Export comparison results to JSON file.
        
        Parameters:
        - filename: Name of JSON file to create
        """
        if not self.results:
            return False
            
        # Create export data with metadata
        export_data = {
            "metadata": {
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scoring_approach": self.scoring_approach,
                "adjustment_method": self.ivss_adjustment_method if self.scoring_approach in ["hybrid_only", "comprehensive"] else "N/A",
                "total_vulnerabilities": len(self.results),
                "user_metadata": self.metadata
            },
            "results": self.results
        }
        
        with open(filename, 'w') as jsonfile:
            json.dump(export_data, jsonfile, indent=2)
                
        return True
    
    def load_from_json(self, filename):
        """
        Load previously saved results from JSON file.
        
        Parameters:
        - filename: Name of JSON file to load
        """
        try:
            with open(filename, 'r') as jsonfile:
                data = json.load(jsonfile)
            
            # Extract results and metadata
            if "results" in data:
                self.results = data["results"]
            else:
                # Handle legacy format (just array of results)
                self.results = data
            
            # Extract metadata if available
            if "metadata" in data:
                metadata = data["metadata"]
                if "scoring_approach" in metadata:
                    self.scoring_approach = metadata["scoring_approach"]
                if "adjustment_method" in metadata:
                    self.ivss_adjustment_method = metadata["adjustment_method"]
                if "user_metadata" in metadata:
                    self.metadata = metadata["user_metadata"]
            
            return True
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading results: {e}")
            return False
        
    def calculate_pearson_correlation(self) -> Dict[str, float]:
        """
        Calculate Pearson correlation coefficients between different scoring methodologies.
        
        Returns:
            Dictionary with correlation coefficients for each score pair
        """
        # Extract scores if we have results
        if not self.results:
            return {"error": "No vulnerability assessment results available"}
        
        # Initialize score lists
        cvss_scores = []
        ivss_scores = []
        hybrid_scores = []
        
        # Extract scores from results with multiple format support
        for result in self.results:
            # Extract CVSS scores
            if 'cvss' in result and 'score' in result['cvss']:
                cvss_score = result['cvss']['score']
                cvss_scores.append(cvss_score)
                
            # Extract IVSS scores (standalone or legacy format)
            ivss_score = None
            if 'standalone_ivss' in result and 'score' in result['standalone_ivss']:
                ivss_score = result['standalone_ivss']['score']
            elif 'ivss' in result and 'score' in result['ivss']:
                ivss_score = result['ivss']['score']
                
            if ivss_score is not None:
                ivss_scores.append(ivss_score)
                
            # Extract hybrid scores if available
            hybrid_score = None
            if 'hybrid_ivss' in result and 'score' in result['hybrid_ivss']:
                hybrid_score = result['hybrid_ivss']['score']
            elif 'hybrid' in result and 'score' in result['hybrid']:
                hybrid_score = result['hybrid']['score']
                
            if hybrid_score is not None:
                hybrid_scores.append(hybrid_score)
        
        # Calculate correlations
        correlations = {}
        
        # Import numpy for correlation calculation
        import numpy as np
        
        # CVSS vs IVSS correlation
        if len(cvss_scores) == len(ivss_scores) and len(cvss_scores) > 1:
            cvss_ivss_corr = np.corrcoef(cvss_scores, ivss_scores)[0, 1]
            correlations["cvss_ivss"] = cvss_ivss_corr
        
        # CVSS vs Hybrid correlation
        if len(cvss_scores) == len(hybrid_scores) and len(cvss_scores) > 1:
            cvss_hybrid_corr = np.corrcoef(cvss_scores, hybrid_scores)[0, 1]
            correlations["cvss_hybrid"] = cvss_hybrid_corr
        
        # IVSS vs Hybrid correlation
        if len(ivss_scores) == len(hybrid_scores) and len(ivss_scores) > 1:
            ivss_hybrid_corr = np.corrcoef(ivss_scores, hybrid_scores)[0, 1]
            correlations["ivss_hybrid"] = ivss_hybrid_corr
        
        return correlations