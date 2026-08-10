"""
Network Comparison Utility

Analyzes vulnerability assessment results across different network architectures
to evaluate how network design affects security risk assessments.
"""

import os
import json
import logging
from matplotlib.lines import Line2D
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import seaborn as sns
from typing import Dict, List, Any, Optional, Tuple

def load_assessment_results(results_dir: str) -> Dict[str, Any]:
    """
    Load assessment results from a results directory.
    
    Args:
        results_dir: Directory containing assessment results
        
    Returns:
        Dictionary containing parsed assessment results
    """
    logger = logging.getLogger("NetworkComparison")
    
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
            
            # Add affected devices count
            vulnerability_data[scenario_name]['affected_devices_count'] = len(scenario_results.get('affected_devices', {}))
    
    return vulnerability_data

def create_network_comparison_dashboard(comparison: Dict[str, Dict[str, Any]], 
                                      statistics: Dict[str, Any],
                                      save_path: Optional[str] = None) -> plt.Figure:
    """
    Create a comprehensive dashboard comparing networks.
    
    Args:
        comparison: Comparison data dictionary
        statistics: Overall statistics dictionary
        save_path: Optional path to save the dashboard
        
    Returns:
        Matplotlib figure object
    """
    # Create data for plotting
    vulnerabilities = list(comparison.keys())
    
    # Set up the main figure with grid layout
    plt.style.use('seaborn-v0_8-whitegrid')
    fig = plt.figure(figsize=(15, 10))
    gs = GridSpec(2, 2, height_ratios=[1.5, 1])
    
    # Vulnerability score differences (top half)
    ax1 = fig.add_subplot(gs[0, :])
    
    # Prepare data - REMOVING CVSS
    ivss_diffs = [comparison[v]["differences"]["standalone_ivss_score_diff"] for v in vulnerabilities]
    hybrid_diffs = [comparison[v]["differences"]["hybrid_ivss_score_diff"] for v in vulnerabilities]
    
    # Set up bar positions
    x = np.arange(len(vulnerabilities))
    width = 0.35  # Wider bars now that we only have 2 instead of 3
    
    # Create bars - CVSS REMOVED
    ax1.bar(x - width/2, ivss_diffs, width, label='IVSS Score Difference', color='#ff7f0e')
    ax1.bar(x + width/2, hybrid_diffs, width, label='Hybrid Score Difference', color='#2ca02c')
    
    # Configure the plot
    ax1.set_title('Score Differences Between Edge/Hidden Network and Standard Network', fontsize=14)
    ax1.set_xlabel('Vulnerability', fontsize=12)
    ax1.set_ylabel('Score Difference (Edge - Standard)', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels([v.split(':')[0] for v in vulnerabilities], rotation=45, ha='right')
    ax1.axhline(y=0, color='gray', linestyle='-', alpha=0.3)
    ax1.legend()
    ax1.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Average sensitivity chart (bottom left)
    ax2 = fig.add_subplot(gs[1, 0])
    
    # Extract data - REMOVING CVSS
    methods = ["IVSS", "Hybrid"]  # Only IVSS and Hybrid
    sensitivities = [statistics["average_sensitivities"]["IVSS"], statistics["average_sensitivities"]["Hybrid"]]
    
    ax2.bar(methods, sensitivities, color=['#ff7f0e', '#2ca02c'])
    ax2.set_title('Average Sensitivity to Network Architecture', fontsize=14)
    ax2.set_xlabel('Scoring System', fontsize=12)
    ax2.set_ylabel('Average Score Difference', fontsize=12)
    ax2.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Most sensitive count chart (bottom right)
    ax3 = fig.add_subplot(gs[1, 1])
    
    # Extract data - REMOVING CVSS
    counts = [statistics["most_sensitive_counts"]["IVSS"], statistics["most_sensitive_counts"]["Hybrid"]]
    
    ax3.pie(counts, labels=methods, autopct='%1.1f%%', startangle=90, 
           colors=['#ff7f0e', '#2ca02c'], 
           explode=[0.05, 0.05])
    ax3.set_title('Most Sensitive Scoring System by Vulnerability', fontsize=14)
    
    # Add single title at the top
    fig.suptitle('Network Architecture Influence on Vulnerability Scoring', fontsize=16, y=0.98)
    
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    # Save figure if path provided
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return fig

def get_severity_category(score):
    """Get severity category from score."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def compare_vulnerabilities(standard_results: Dict[str, Dict[str, Any]], 
                           edge_results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Compare vulnerability assessments across network architectures.
    
    Args:
        standard_results: Vulnerability data from standard network
        edge_results: Vulnerability data from edge/hidden network
        
    Returns:
        Dictionary containing comparison results
    """
    comparison = {}
    
    # Find common vulnerabilities
    common_vulnerabilities = set(standard_results.keys()) & set(edge_results.keys())
    
    for vuln_name in common_vulnerabilities:
        standard_data = standard_results[vuln_name]
        edge_data = edge_results[vuln_name]
        
        # Calculate differences
        comparison[vuln_name] = {
            "standard_network": {
                "cvss_score": standard_data.get("cvss_score", 0),
"standalone_ivss_score": standard_data.get("standalone_ivss_score", 0),
                "hybrid_ivss_score": standard_data.get("hybrid_ivss_score", 0),
                "affected_devices": standard_data.get("affected_devices_count", 0)
            },
            "edge_network": {
                "cvss_score": edge_data.get("cvss_score", 0),
                "standalone_ivss_score": edge_data.get("standalone_ivss_score", 0),
                "hybrid_ivss_score": edge_data.get("hybrid_ivss_score", 0),
                "affected_devices": edge_data.get("affected_devices_count", 0)
            },
            "differences": {
                "cvss_score_diff": edge_data.get("cvss_score", 0) - standard_data.get("cvss_score", 0),
                "standalone_ivss_score_diff": edge_data.get("standalone_ivss_score", 0) - standard_data.get("standalone_ivss_score", 0),
                "hybrid_ivss_score_diff": edge_data.get("hybrid_ivss_score", 0) - standard_data.get("hybrid_ivss_score", 0),
                "cvss_sensitivity": abs(edge_data.get("cvss_score", 0) - standard_data.get("cvss_score", 0)),
                "ivss_sensitivity": abs(edge_data.get("standalone_ivss_score", 0) - standard_data.get("standalone_ivss_score", 0)),
                "hybrid_sensitivity": abs(edge_data.get("hybrid_ivss_score", 0) - standard_data.get("hybrid_ivss_score", 0)),
                "affected_devices_diff": edge_data.get("affected_devices_count", 0) - standard_data.get("affected_devices_count", 0)
            }
        }
        
        # Calculate which scoring system shows highest sensitivity to network architecture
        sensitivity_values = [
            ("CVSS", comparison[vuln_name]["differences"]["cvss_sensitivity"]),
            ("IVSS", comparison[vuln_name]["differences"]["ivss_sensitivity"]),
            ("Hybrid", comparison[vuln_name]["differences"]["hybrid_sensitivity"])
        ]
        
        # Sort by sensitivity value (descending)
        sensitivity_values.sort(key=lambda x: x[1], reverse=True)
        comparison[vuln_name]["most_sensitive"] = sensitivity_values[0][0]
        comparison[vuln_name]["sensitivity_ranking"] = sensitivity_values
    
    return comparison

def calculate_overall_statistics(comparison: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate overall statistics from comparison data.
    
    Args:
        comparison: Comparison results dictionary
        
    Returns:
        Dictionary containing overall statistics
    """
    if not comparison:
        return {}
    
    # Initialize counters
    most_sensitive_counts = {"CVSS": 0, "IVSS": 0, "Hybrid": 0}
    total_sensitivities = {"CVSS": [], "IVSS": [], "Hybrid": []}
    
    # Process each vulnerability
    for vuln_name, vuln_data in comparison.items():
        # Count most sensitive metric
        most_sensitive = vuln_data.get("most_sensitive")
        if most_sensitive in most_sensitive_counts:
            most_sensitive_counts[most_sensitive] += 1
            
        # Collect sensitivity values
        diffs = vuln_data.get("differences", {})
        total_sensitivities["CVSS"].append(diffs.get("cvss_sensitivity", 0))
        total_sensitivities["IVSS"].append(diffs.get("ivss_sensitivity", 0))
        total_sensitivities["Hybrid"].append(diffs.get("hybrid_sensitivity", 0))
    
    # Calculate average sensitivities
    avg_sensitivities = {
        method: sum(values) / len(values) if values else 0 
        for method, values in total_sensitivities.items()
    }
    
    # Calculate highest average sensitivity
    highest_avg = max(avg_sensitivities.items(), key=lambda x: x[1])
    
    return {
        "most_sensitive_counts": most_sensitive_counts,
        "average_sensitivities": avg_sensitivities,
        "highest_average_sensitivity": highest_avg[0],
        "vulnerability_count": len(comparison)
    }

def create_score_difference_chart(comparison, save_path=None):
    """
    Create a chart showing vulnerability score differences between networks.
    Only showing IVSS and Hybrid scores (no CVSS).
    
    Args:
        comparison: Comparison data dictionary
        save_path: Optional path to save the chart
        
    Returns:
        Matplotlib figure object
    """
    # Create data for plotting
    vulnerabilities = list(comparison.keys())
    
    # Prepare data - IVSS and Hybrid only
    ivss_diffs = [comparison[v]["differences"]["standalone_ivss_score_diff"] for v in vulnerabilities]
    hybrid_diffs = [comparison[v]["differences"]["hybrid_ivss_score_diff"] for v in vulnerabilities]
    
    # Set up the figure
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Set up bar positions
    x = np.arange(len(vulnerabilities))
    width = 0.35  # Wider bars with only 2 data points
    
    # Create bars - IVSS and Hybrid only
    ax.bar(x - width/2, ivss_diffs, width, label='IVSS Score Difference', color='#ff7f0e')
    ax.bar(x + width/2, hybrid_diffs, width, label='Hybrid Score Difference', color='#2ca02c')
    
    # Configure the plot
    ax.set_title('Score Differences Between Edge/Hidden Network and Standard Network', fontsize=14)
    ax.set_xlabel('Vulnerability', fontsize=12)
    ax.set_ylabel('Score Difference (Edge - Standard)', fontsize=12)
    ax.set_xticks(x)
    ax.set_xticklabels([v.split(':')[0] for v in vulnerabilities], rotation=45, ha='right')
    ax.axhline(y=0, color='gray', linestyle='-', alpha=0.3)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    
    # Save figure if path provided
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return fig

def create_sensitivity_chart(statistics, save_path=None):
    """
    Create a chart showing average sensitivity to network architecture.
    Only showing IVSS and Hybrid data (no CVSS).
    
    Args:
        statistics: Overall statistics dictionary
        save_path: Optional path to save the chart
        
    Returns:
        Matplotlib figure object
    """
    # Extract data - IVSS and Hybrid only
    methods = ["IVSS", "Hybrid"]
    sensitivities = [statistics["average_sensitivities"]["IVSS"], statistics["average_sensitivities"]["Hybrid"]]
    
    # Set up the figure
    plt.style.use('seaborn-v0_8-whitegrid')
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Create bars
    ax.bar(methods, sensitivities, color=['#ff7f0e', '#2ca02c'])
    ax.set_title('Average Sensitivity to Network Architecture', fontsize=14)
    ax.set_xlabel('Scoring System', fontsize=12)
    ax.set_ylabel('Average Score Difference', fontsize=12)
    ax.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    
    # Save figure if path provided
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    
    return fig

def generate_score_difference_json(comparison, output_path=None):
    """
    Create a simple JSON of vulnerability score differences between networks.
    This focuses just on the data being visualized in charts.
    
    Args:
        comparison: Comparison data dictionary
        output_path: Optional path to save the JSON
        
    Returns:
        Dictionary containing score differences data and the file path if saved
    """
    # Create data structure
    vulnerabilities = list(comparison.keys())
    
    # Simple structure focused on visualization data
    score_diff_data = {
        "vulnerabilities": [],
        "average_sensitivities": {
            "IVSS": 0,
            "Hybrid": 0
        },
        "most_sensitive_counts": {
            "IVSS": 0,
            "Hybrid": 0
        }
    }
    
    # Calculate total sensitivities for average
    total_ivss = 0
    total_hybrid = 0
    ivss_count = 0
    hybrid_count = 0
    
    # Process each vulnerability
    for vuln_name in vulnerabilities:
        vuln_data = comparison[vuln_name]
        
        # Get short name (remove CVE prefix if present)
        short_name = vuln_name.split(':')[0] if ':' in vuln_name else vuln_name
        
        # Create vulnerability entry
        vuln_entry = {
            "name": short_name,
            "full_name": vuln_name,
            "differences": {
                "ivss_score_diff": vuln_data["differences"]["standalone_ivss_score_diff"],
                "hybrid_score_diff": vuln_data["differences"]["hybrid_ivss_score_diff"]
            },
            "most_sensitive": vuln_data.get("most_sensitive", "")
        }
        
        # Add to vulnerability list
        score_diff_data["vulnerabilities"].append(vuln_entry)
        
        # Update sensitivity counters
        total_ivss += abs(vuln_data["differences"]["standalone_ivss_score_diff"])
        total_hybrid += abs(vuln_data["differences"]["hybrid_ivss_score_diff"])
        
        # Count which scoring method was most sensitive for this vulnerability
        if vuln_data.get("most_sensitive") == "IVSS":
            score_diff_data["most_sensitive_counts"]["IVSS"] += 1
        elif vuln_data.get("most_sensitive") == "Hybrid":
            score_diff_data["most_sensitive_counts"]["Hybrid"] += 1
    
    # Calculate averages
    if vulnerabilities:
        score_diff_data["average_sensitivities"]["IVSS"] = total_ivss / len(vulnerabilities)
        score_diff_data["average_sensitivities"]["Hybrid"] = total_hybrid / len(vulnerabilities)
    
    # Save to file if path provided
    if output_path:
        try:
            with open(output_path, 'w') as f:
                import json
                json.dump(score_diff_data, f, indent=2)
            return score_diff_data, output_path
        except Exception as e:
            print(f"Error saving JSON: {e}")
            return score_diff_data, None
    
    return score_diff_data, None

def generate_network_comparison(standard_results_dir: str, edge_results_dir: str, 
                             output_charts_prefix: str) -> None:
    """
    Generate a comparison of vulnerability assessments across network architectures.
    Creates visualizations but no reports.
    
    Args:
        standard_results_dir: Directory containing standard network results
        edge_results_dir: Directory containing edge/hidden network results
        output_charts_prefix: Prefix path for visualization files
    """
    logger = logging.getLogger("NetworkComparison")
    logger.info("Generating network architecture comparison")
    
    # Load assessment results from both networks
    standard_results = load_assessment_results(standard_results_dir)
    edge_results = load_assessment_results(edge_results_dir)
    
    if not standard_results or not edge_results:
        logger.error("Failed to load assessment results from one or both networks")
        return
    
    # Extract vulnerability data
    standard_vuln_data = extract_vulnerability_data(standard_results)
    edge_vuln_data = extract_vulnerability_data(edge_results)
    
    # Compare vulnerabilities across networks - FIXED ORDER
    comparison = compare_vulnerabilities(standard_vuln_data, edge_vuln_data)
    statistics = calculate_overall_statistics(comparison)
    
    # Define a directory for combined results if needed
    output_dir = os.path.dirname(output_charts_prefix)
    
    # Save score differences JSON
    score_diff_json_path = f"{output_charts_prefix}_score_differences.json"
    score_diff_data, json_path = generate_score_difference_json(comparison, score_diff_json_path)

    if json_path:
        logger.info(f"Score difference JSON saved to: {json_path}")
    
    if not comparison:
        logger.error("No common vulnerabilities found for comparison")
        return
    
    # Define output file paths for the two separate visualizations
    score_diff_chart_path = f"{output_charts_prefix}_score_differences.png"
    sensitivity_chart_path = f"{output_charts_prefix}_sensitivity.png"
    dashboard_path = f"{output_charts_prefix}_dashboard.png"
    
    # Create visualizations
    logger.info("Creating network comparison visualizations")
    
    # Create score differences chart
    logger.info(f"Creating score difference chart: {score_diff_chart_path}")
    create_score_difference_chart(comparison, score_diff_chart_path)
    
    # Create sensitivity chart
    logger.info(f"Creating sensitivity chart: {sensitivity_chart_path}")
    create_sensitivity_chart(statistics, sensitivity_chart_path)
    
    # Create dashboard
    logger.info(f"Creating comprehensive dashboard: {dashboard_path}")
    create_network_comparison_dashboard(comparison, statistics, dashboard_path)
    
    # Log completion
    logger.info(f"Network comparison visualizations completed")
    logger.info(f"Visualizations saved with prefix: {output_charts_prefix}")