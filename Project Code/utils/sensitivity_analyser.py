"""
Sensitivity Analysis Utility

Analyzes vulnerability assessment results across different parameter variations
to evaluate how sensitive scoring methodologies are to parameter changes.
"""

import os
import json
import logging
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, List, Any, Optional

def load_assessment_results(results_dir: str) -> Dict[str, Any]:
    """
    Load assessment results from a results directory.
    
    Args:
        results_dir: Directory containing assessment results
        
    Returns:
        Dictionary containing parsed assessment results
    """
    logger = logging.getLogger("SensitivityAnalysis")
    
    # Path to assessment results JSON
    results_path = os.path.join(results_dir, "assessment_results.json")
    
    if not os.path.exists(results_path):
        logger.error(f"Assessment results not found at {results_path}")
        return {}
    
    try:
        with open(results_path, 'r') as f:
            results = json.load(f)
        logger.info(f"Loaded assessment results from {results_path}")
        return results
    except Exception as e:
        logger.error(f"Error loading assessment results: {e}")
        return {}

def extract_vulnerability_data(results: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Extract vulnerability data from assessment results.
    
    Args:
        results: Assessment results dictionary
        
    Returns:
        Dictionary mapping vulnerability names to their data
    """
    vulnerability_data = {}
    
    for scenario_name, scenario_results in results.items():
        # Skip scenarios with errors
        if isinstance(scenario_results, dict) and "error" in scenario_results:
            continue
            
        # Extract vulnerability data if available
        if 'vulnerability_data' in scenario_results:
            vulnerability_data[scenario_name] = scenario_results['vulnerability_data']
    
    return vulnerability_data

def analyze_sensitivity(variations: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Analyze sensitivity of scoring methodologies across parameter variations.
    
    Args:
        variations: Dictionary mapping variation names to vulnerability data
        
    Returns:
        Dictionary containing sensitivity analysis results
    """
    logger = logging.getLogger("SensitivityAnalysis")
    
    analysis = {
        "variation_count": len(variations),
        "vulnerabilities": {},
        "scoring_methods": {
            "cvss": {"sensitivity": 0.0, "std_dev": 0.0},
            "ivss": {"sensitivity": 0.0, "std_dev": 0.0},
            "hybrid": {"sensitivity": 0.0, "std_dev": 0.0}
        },
        "max_variations": []
    }
    
    # Get common vulnerabilities across all variations
    common_vulns = set()
    for var_name, vulns in variations.items():
        if not common_vulns:
            common_vulns = set(vulns.keys())
        else:
            common_vulns &= set(vulns.keys())
    
    # Analyze each vulnerability
    for vuln_name in common_vulns:
        
        # Collect scores across variations
        cvss_scores = []
        ivss_scores = []
        hybrid_scores = []
        
        for var_name, vulns in variations.items():
            if vuln_name in vulns:
                vuln_data = vulns[vuln_name]
                cvss_score = vuln_data.get("cvss_score", 0)
                ivss_score = vuln_data.get("standalone_ivss_score", 0)
                hybrid_score = vuln_data.get("hybrid_ivss_score", 0)
                
                cvss_scores.append(cvss_score)
                ivss_scores.append(ivss_score)
                hybrid_scores.append(hybrid_score)
                
        # Calculate score sensitivity (range / mean)
        cvss_sensitivity = 0
        ivss_sensitivity = 0
        hybrid_sensitivity = 0
        
        if cvss_scores:
            cvss_range = max(cvss_scores) - min(cvss_scores)
            cvss_mean = sum(cvss_scores) / len(cvss_scores)
            cvss_sensitivity = cvss_range / cvss_mean if cvss_mean > 0 else 0
            cvss_std = np.std(cvss_scores)
        
        if ivss_scores:
            ivss_range = max(ivss_scores) - min(ivss_scores)
            ivss_mean = sum(ivss_scores) / len(ivss_scores)
            ivss_sensitivity = ivss_range / ivss_mean if ivss_mean > 0 else 0
            ivss_std = np.std(ivss_scores)
        
        if hybrid_scores:
            hybrid_range = max(hybrid_scores) - min(hybrid_scores)
            hybrid_mean = sum(hybrid_scores) / len(hybrid_scores)
            hybrid_sensitivity = hybrid_range / hybrid_mean if hybrid_mean > 0 else 0
            hybrid_std = np.std(hybrid_scores)
        
        # Store vulnerability analysis
        analysis["vulnerabilities"][vuln_name] = {
            "cvss": {
                "scores": cvss_scores,
                "mean": cvss_mean if cvss_scores else 0,
                "range": cvss_range if cvss_scores else 0,
                "sensitivity": cvss_sensitivity,
                "std_dev": cvss_std if cvss_scores else 0
            },
            "ivss": {
                "scores": ivss_scores,
                "mean": ivss_mean if ivss_scores else 0,
                "range": ivss_range if ivss_scores else 0,
                "sensitivity": ivss_sensitivity,
                "std_dev": ivss_std if ivss_scores else 0
            },
            "hybrid": {
                "scores": hybrid_scores,
                "mean": hybrid_mean if hybrid_scores else 0,
                "range": hybrid_range if hybrid_scores else 0,
                "sensitivity": hybrid_sensitivity,
                "std_dev": hybrid_std if hybrid_scores else 0
            }
        }
        
        # Determine most sensitive scoring method
        sensitivities = [
            ("cvss", cvss_sensitivity),
            ("ivss", ivss_sensitivity),
            ("hybrid", hybrid_sensitivity)
        ]
        sensitivities.sort(key=lambda x: x[1], reverse=True)
        
        analysis["vulnerabilities"][vuln_name]["most_sensitive"] = sensitivities[0][0]
        analysis["vulnerabilities"][vuln_name]["sensitivity_ranking"] = sensitivities
    
    # Calculate overall statistics
    cvss_sensitivities = [vuln["cvss"]["sensitivity"] for vuln in analysis["vulnerabilities"].values()]
    ivss_sensitivities = [vuln["ivss"]["sensitivity"] for vuln in analysis["vulnerabilities"].values()]
    hybrid_sensitivities = [vuln["hybrid"]["sensitivity"] for vuln in analysis["vulnerabilities"].values()]
    
    analysis["scoring_methods"]["cvss"]["sensitivity"] = sum(cvss_sensitivities) / len(cvss_sensitivities) if cvss_sensitivities else 0
    analysis["scoring_methods"]["cvss"]["std_dev"] = np.std(cvss_sensitivities) if cvss_sensitivities else 0
    
    analysis["scoring_methods"]["ivss"]["sensitivity"] = sum(ivss_sensitivities) / len(ivss_sensitivities) if ivss_sensitivities else 0
    analysis["scoring_methods"]["ivss"]["std_dev"] = np.std(ivss_sensitivities) if ivss_sensitivities else 0
    
    analysis["scoring_methods"]["hybrid"]["sensitivity"] = sum(hybrid_sensitivities) / len(hybrid_sensitivities) if hybrid_sensitivities else 0
    analysis["scoring_methods"]["hybrid"]["std_dev"] = np.std(hybrid_sensitivities) if hybrid_sensitivities else 0
    
    # Determine overall most sensitive method
    method_sensitivities = [
        ("CVSS", analysis["scoring_methods"]["cvss"]["sensitivity"]),
        ("IVSS", analysis["scoring_methods"]["ivss"]["sensitivity"]),
        ("Hybrid", analysis["scoring_methods"]["hybrid"]["sensitivity"])
    ]
    method_sensitivities.sort(key=lambda x: x[1], reverse=True)
    analysis["max_variations"] = method_sensitivities
    
    # Count most sensitive instances
    sensitivity_counts = {"CVSS": 0, "IVSS": 0, "Hybrid": 0}
    for vuln in analysis["vulnerabilities"].values():
        most_sensitive = vuln.get("most_sensitive", "").upper()
        if most_sensitive == "CVSS":
            sensitivity_counts["CVSS"] += 1
        elif most_sensitive == "IVSS":
            sensitivity_counts["IVSS"] += 1
        elif most_sensitive == "HYBRID":
            sensitivity_counts["Hybrid"] += 1
    
    analysis["sensitivity_counts"] = sensitivity_counts
    
    return analysis
    
def create_sensitivity_chart(analysis: Dict[str, Any], save_path: Optional[str] = None) -> plt.Figure:
    """
    Create a chart showing sensitivity of IVSS and Hybrid scoring methodologies only.
    CVSS data is completely excluded from visualization.
    
    Args:
        analysis: Analysis data dictionary
        save_path: Optional path to save the chart
        
    Returns:
        Matplotlib figure object
    """
    # Setup the figure with multiple subplots
    plt.style.use('seaborn-v0_8-whitegrid')
    fig = plt.figure(figsize=(15, 10))
    
    # Use a fixed grid layout for all vulnerabilities
    rows, cols = 3, 3  # 3x3 grid allows for up to 8 vulnerabilities (1 spot for overall chart)
    
    # 1. IVSS and Hybrid sensitivity comparison (top left)
    ax1 = plt.subplot2grid((rows, cols), (0, 0), colspan=3)
    
    # Only include IVSS and Hybrid methods
    methods = ["IVSS", "Hybrid"]
    sensitivities = [
        analysis["scoring_methods"]["ivss"]["sensitivity"],
        analysis["scoring_methods"]["hybrid"]["sensitivity"]
    ]
    std_devs = [
        analysis["scoring_methods"]["ivss"]["std_dev"],
        analysis["scoring_methods"]["hybrid"]["std_dev"]
    ]
    
    ax1.bar(methods, sensitivities, yerr=std_devs, capsize=10,
          color=['#ff7f0e', '#2ca02c'])
    
    ax1.set_title('Average Parameter Sensitivity by Scoring Method', fontsize=14)
    ax1.set_ylabel('Sensitivity (Range/Mean)', fontsize=12)
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Calculate total sensitivity for each vulnerability to determine the top ones
    vuln_names = list(analysis["vulnerabilities"].keys())
    vuln_total_sensitivities = []
    
    for vuln_name in vuln_names:
        vuln_data = analysis["vulnerabilities"][vuln_name]
        # Only include IVSS and Hybrid sensitivity in total
        total_sens = (vuln_data["ivss"]["sensitivity"] + 
                     vuln_data["hybrid"]["sensitivity"])
        vuln_total_sensitivities.append((vuln_name, total_sens))
    
    # Sort by total sensitivity and take top 8
    vuln_total_sensitivities.sort(key=lambda x: x[1], reverse=True)
    top_vulns = vuln_total_sensitivities[:8]  # Limit to 8 vulnerabilities
    
    # Create subplots for each top vulnerability
    for i, (vuln_name, _) in enumerate(top_vulns):
        row = 1 + (i // cols)
        col = i % cols
        
        ax = plt.subplot2grid((rows, cols), (row, col))
        
        vuln_data = analysis["vulnerabilities"][vuln_name]
        
        # Get only IVSS and Hybrid sensitivities
        vuln_sensitivities = [
            vuln_data["ivss"]["sensitivity"],
            vuln_data["hybrid"]["sensitivity"]
        ]
        
        # Display vulnerability name (or CVE ID if available)
        display_name = vuln_name
        if ":" in vuln_name:
            display_name = vuln_name.split(":")[0]
        elif len(vuln_name) > 15:
            display_name = vuln_name[:15]
        
        ax.bar(methods, vuln_sensitivities, 
              color=['#ff7f0e', '#2ca02c'])
        
        ax.set_title(display_name, fontsize=12)
        ax.set_xticks(methods)
        ax.set_xticklabels(methods, rotation=45, ha='right')
        ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add overall title
    most_sensitive = "Hybrid" if analysis["scoring_methods"]["hybrid"]["sensitivity"] > analysis["scoring_methods"]["ivss"]["sensitivity"] else "IVSS"
    fig.suptitle('Vulnerability Scoring Method Parameter Sensitivity Analysis', fontsize=16, y=0.98)
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Save figure if path provided
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return fig

def create_combined_visualization(data_file: str, output_path: str) -> None:
    """
    Create a combined visualization with IVSS and Hybrid data only.
    
    Args:
        data_file: Path to the combined vulnerability data file
        output_path: Path to save the visualization
    """
    import matplotlib.pyplot as plt
    import numpy as np
    import json
    import os
    import logging
    
    logger = logging.getLogger("SensitivityAnalysis")
    
    # Load the combined data
    with open(data_file, 'r') as f:
        network_data = json.load(f)
    
    if not network_data:
        logger.error("No data found for visualization")
        return
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Create figure with the needed layout
    plt.figure(figsize=(14, 10))
    
    # Setup grid for the visualization - just 2 rows
    gs = plt.GridSpec(2, 1, height_ratios=[1, 2])
    
    # 1. Average Parameter Sensitivity (top)
    ax1 = plt.subplot(gs[0])
    
    # Only use IVSS and Hybrid methods
    methods = ["IVSS", "Hybrid"]
    
    # Get sensitivities from the combined data (average across networks)
    combined_sensitivities = {
        "ivss": 0,
        "hybrid": 0
    }
    
    # Get standard deviations
    std_devs = {
        "ivss": 0,
        "hybrid": 0
    }
    
    # Calculate average sensitivities across all networks
    networks_with_data = 0
    for network, data in network_data.items():
        if "scoring_methods" in data:
            networks_with_data += 1
            for method in ["ivss", "hybrid"]:
                if method in data["scoring_methods"]:
                    combined_sensitivities[method] += data["scoring_methods"][method]["sensitivity"]
                    std_devs[method] += data["scoring_methods"][method].get("std_dev", 0)
    
    # Divide by number of networks
    if networks_with_data > 0:
        for method in combined_sensitivities:
            combined_sensitivities[method] /= networks_with_data
            std_devs[method] /= networks_with_data
    
    # Create bar charts for methods
    sensitivities = [
        combined_sensitivities["ivss"],
        combined_sensitivities["hybrid"]
    ]
    
    error_bars = [
        std_devs["ivss"],
        std_devs["hybrid"]
    ]
    
    colors = ['#ff7f0e', '#2ca02c']  # IVSS, Hybrid
    
    # Add the bars with error bars
    bars = ax1.bar(methods, sensitivities, yerr=error_bars, capsize=10, color=colors)
    
    ax1.set_title('Average Parameter Sensitivity by Scoring Method', fontsize=14)
    ax1.set_ylabel('Sensitivity (Range/Mean)', fontsize=12)
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # 2. Bottom section: Individual vulnerability charts in a grid
    # Get top vulnerabilities across all networks
    all_vulnerabilities = {}
    
    for network, data in network_data.items():
        for vuln_name, vuln_data in data.get("vulnerabilities", {}).items():
            if vuln_name not in all_vulnerabilities:
                # Calculate average sensitivity for IVSS and Hybrid only
                ivss_sens = vuln_data.get("ivss", {}).get("sensitivity", 0)
                hybrid_sens = vuln_data.get("hybrid", {}).get("sensitivity", 0)
                avg_sensitivity = (ivss_sens + hybrid_sens) / 2
                    
                all_vulnerabilities[vuln_name] = {
                    "avg_sensitivity": avg_sensitivity,
                    "data": {network: vuln_data}
                }
            else:
                all_vulnerabilities[vuln_name]["data"][network] = vuln_data
    
    # Sort vulnerabilities by average sensitivity
    sorted_vulns = sorted(all_vulnerabilities.items(), 
                         key=lambda x: x[1]["avg_sensitivity"], 
                         reverse=True)
    
    # Take top 8 vulnerabilities
    top_vulns = sorted_vulns[:min(8, len(sorted_vulns))]
    
    # Create subplot grid for vulnerabilities
    vuln_grid = plt.GridSpec(3, 3, wspace=0.3, hspace=0.4)
    vuln_grid.update(top=0.9, bottom=0.1)
    
    # Create a subplot for each vulnerability
    for i, (vuln_name, vuln_info) in enumerate(top_vulns):
        row = 1 + (i // 3)
        col = i % 3
        
        # Place in the bottom section's grid
        ax = plt.subplot(vuln_grid[row, col])
        
        # Clean up vulnerability name for display
        if ":" in vuln_name:
            display_name = vuln_name.split(":")[0]
        else:
            display_name = vuln_name
        
        # For each network, get the sensitivity values
        for network, vuln_data in vuln_info["data"].items():
            # Get sensitivities for each method (IVSS and Hybrid only)
            method_values = [
                vuln_data.get("ivss", {}).get("sensitivity", 0),
                vuln_data.get("hybrid", {}).get("sensitivity", 0)
            ]
            
            # Plot the bars
            ax.bar(methods, method_values, color=colors)
        
        # Set title and format
        ax.set_title(display_name, fontsize=10)
        ax.set_xticks([0, 1])
        ax.set_xticklabels(methods, rotation=45, ha='right', fontsize=9)
        ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add overall title
    plt.suptitle('Vulnerability Scoring Method Parameter Sensitivity', fontsize=16, y=0.98)
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Save the visualization
    try:
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"Combined visualization saved to {output_path}")
    except Exception as e:
        logger.error(f"Error saving combined visualization: {e}")
    
    plt.close()

def generate_sensitivity_analysis(variation_results: Dict[str, str],
                                output_charts: str,
                                return_analysis: bool = False) -> Optional[Dict[str, Any]]:
    """
    Generate a sensitivity analysis visualization (no report).
    
    Args:
        variation_results: Dictionary mapping variation names to results directories
        output_charts: Path to save the visualization
        return_analysis: Whether to return the analysis data
        
    Returns:
        Analysis data dictionary if return_analysis is True, otherwise None
    """
    logger = logging.getLogger("SensitivityAnalysis")
    logger.info("Generating sensitivity analysis")
    
    # Load vulnerability data from each variation
    variations_data = {}
    
    for variation_name, results_dir in variation_results.items():
        # Load assessment results
        results = load_assessment_results(results_dir)
        
        if not results:
            logger.warning(f"No assessment results found for variation: {variation_name}")
            continue
        
        # Extract vulnerability data
        vuln_data = extract_vulnerability_data(results)
        
        if not vuln_data:
            logger.warning(f"No vulnerability data found for variation: {variation_name}")
            continue
        
        # Store vulnerability data for this variation
        variations_data[variation_name] = vuln_data
    
    if len(variations_data) < 2:
        logger.error("Insufficient variation data for analysis")
        return None if return_analysis else None
    
    # Analyze sensitivity across variations
    analysis = analyze_sensitivity(variations_data)
    
    # Create visualization
    logger.info("Creating sensitivity visualization")
    create_sensitivity_chart(analysis, output_charts)
    
    logger.info(f"Sensitivity visualization saved to {output_charts}")
    
    # Return the analysis data if requested
    return analysis if return_analysis else None