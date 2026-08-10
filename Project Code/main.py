#!/usr/bin/env python3
"""
Vulnerability Assessment Main Runner

Provides a streamlined interface for running vulnerability assessments on 
industrial control system networks with structured output directories.
"""

import os
import copy
import sys
import importlib
import re
import json
import argparse
import traceback
import logging
import shutil
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from simulation.simulation_config import SIMULATIONS
from utils.run_analysis import VulnerabilityAssessmentManager

def setup_logging(verbose: bool = True) -> logging.Logger:
    """
    Set up logging for the application.
    
    Args:
        verbose: Whether to enable verbose logging
        
    Returns:
        Logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("VulnerabilityAssessment")
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("VulnerabilityDetector").setLevel(logging.DEBUG)
    return logger

def run_simulation(simulation_name: str) -> Tuple[str, str]:
    """
    Run the specified NS3 network simulation.
    
    Args:
        simulation_name: Name of the simulation configuration
        
    Returns:
        Tuple of (simulation output, results directory)
    """
    logger = logging.getLogger("Simulation")
    
    # Get randomization settings
    sim_randomized = os.environ.get("SIM_RANDOMIZE", "").lower() in ["true", "1", "yes"]
    seed = os.environ.get("SIM_SEED")
    
    logger.info(f"Running ICS network simulation: {simulation_name}")
    logger.info(f"Randomization: {'ENABLED' if sim_randomized else 'DISABLED'}")
    if sim_randomized and seed:
        logger.info(f"Using seed: {seed}")
    
    # Set fixed simulation time
    simulation_time = 300
    
    # Get simulation configuration
    if simulation_name not in SIMULATIONS:
        logger.error(f"Unknown simulation configuration: {simulation_name}")
        return None, None
    
    # Choose the appropriate simulation script based on simulation type
    if simulation_name == "standard_network":
        sim_script_path = os.path.join(os.path.dirname(__file__), "simulation", "standard_simulation.py")
    else:  # edge_hidden_network
        sim_script_path = os.path.join(os.path.dirname(__file__), "simulation", "hidden_simulation.py")
    
    cmd_args = []
    cmd_args.append(f"--time={simulation_time}")
    cmd_args_str = " ".join(cmd_args)
    
    # Set up environment for the simulation
    env = os.environ.copy()
    env["SIMULATION_CONFIG"] = simulation_name
    
    # Create results directory - use environment variable if provided
    if "RESULTS_DIR" in os.environ:
        results_dir = os.environ["RESULTS_DIR"]
        logger.info(f"Using specified results directory: {results_dir}")
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_dir = os.path.join(os.path.dirname(__file__), "results", 
                                  f"{simulation_name}_run_{timestamp}")
        
    os.makedirs(results_dir, exist_ok=True)
    
    # Create PCAP directory
    pcap_dir = os.path.join(results_dir, "pcap")
    os.makedirs(pcap_dir, exist_ok=True)
    logger.info(f"Created PCAP directory: {pcap_dir}")
    env["SIM_PCAP_DIR"] = pcap_dir
    
    # Run the NS3 simulation
    import subprocess
    ns3_command = f"cd ~/ns-allinone-3.43/ns-3.43 && ./ns3 run {sim_script_path} -- {cmd_args_str}"
    
    logger.info(f"Running command: {ns3_command}")
    logger.info(f"Using simulation configuration: {simulation_name}")
    
    try:
        # Run the command with the environment variable
        process = subprocess.Popen(ns3_command, shell=True, stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, env=env)
        stdout, stderr = process.communicate()
        
        # Check for errors
        if process.returncode != 0:
            logger.error("Simulation encountered an error")
            logger.error(stderr.decode('utf-8'))
            return None, None
        
        # Decode output
        stdout_str = stdout.decode('utf-8')
        stderr_str = stderr.decode('utf-8')
        combined_output = stdout_str + "\n\n" + stderr_str
        
        # Save output to file
        output_path = os.path.join(results_dir, "simulation_output.txt")
        with open(output_path, "w") as f:
            f.write(combined_output)
        
        logger.info(f"Simulation completed and output saved to {results_dir}")
        return combined_output, results_dir
        
    except Exception as e:
        logger.error(f"Error running simulation: {e}")
        return None, None

def run_network_scanner(simulation_output: str, results_dir: str, 
                     simulation_name: str, randomized: bool = False) -> Dict:
    """
    Run network scanner to discover devices and build network understanding.
    """
    logger = logging.getLogger("Scanner")
    logger.info(f"DEBUG: Starting network scanner with results_dir: {results_dir}")
    logger.info(f"Running network scanner for {simulation_name} simulation")
    logger.info(f"Randomization mode: {'ENABLED' if randomized else 'DISABLED (deterministic)'}")
    
    # Run the scanner with direct execution
    from scanning.network_scanner import NetworkScanner
    
    try:
        # Set up environment variables
        os.environ["SCAN_RESULTS_DIR"] = results_dir
        os.environ["SIMULATION_TYPE"] = simulation_name
        os.environ["RANDOMIZED_MODE"] = "1" if randomized else "0"
        
        # Save simulation output to a file
        output_file = os.path.join(results_dir, "simulation_output.txt")
        with open(output_file, 'w') as f:
            f.write(simulation_output)
        
        # Create scanner instance
        scanner = NetworkScanner(
            output_dir=results_dir,
            simulation_type=simulation_name
            #randomised=randomized
        )
        
        # Process simulation output (this will generate comprehensive_results.json)
        scanner.parse_simulation_output(output_file)
        
        # Verify the comprehensive results file was created
        comprehensive_file = os.path.join(results_dir, f"{simulation_name}_comprehensive_results.json")
        
        if os.path.exists(comprehensive_file):
            logger.info(f"Scanner successfully created comprehensive results at {comprehensive_file}")
            return comprehensive_file
        else:
            logger.error(f"Comprehensive results file not found at {comprehensive_file}")
            return None
            
    except Exception as e:
        logger.error(f"Error running scanner: {e}")
        logger.error(f"DEBUG: Error traceback: {traceback.format_exc()}")
        return None

def cleanup_visualization_files(standard_dir, hidden_dir, combined_dir):
    """
    Clean up visualization files from source directories after they've been copied to combined_dir.
    
    Args:
        standard_dir: Standard network results directory
        hidden_dir: Edge/hidden network results directory
        combined_dir: Combined results directory
    """
    import os
    import glob
    import logging
    
    logger = logging.getLogger("Cleanup")
    logger.info("Cleaning up visualization files from source directories")
    
    # Files to look for (visualization patterns)
    viz_patterns = [
        "*_discovery_visualization.png",
        "*_scan_visualization.png",
        "vulnerability_dashboard.png",
        "vulnerability_report.md"
    ]
    
    # Process standard directory
    if standard_dir and os.path.exists(standard_dir):
        for pattern in viz_patterns:
            viz_files = glob.glob(os.path.join(standard_dir, pattern))
            for file_path in viz_files:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to delete {file_path}: {e}")
    
    # Process hidden directory
    if hidden_dir and os.path.exists(hidden_dir):
        for pattern in viz_patterns:
            viz_files = glob.glob(os.path.join(hidden_dir, pattern))
            for file_path in viz_files:
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted: {file_path}")
                except Exception as e:
                    logger.error(f"Failed to delete {file_path}: {e}")
    
    logger.info("Visualization file cleanup completed")

def run_vulnerability_assessment(results_dir: str, simulation_name: str, 
                          run_common_scenarios: bool = False) -> Dict[str, Any]:
    """
    Run vulnerability assessment for the specified simulation.
    """
    logger = logging.getLogger("Assessment")
    logger.info(f"Running vulnerability assessment for {simulation_name}")
    
    # Create vulnerability assessment manager
    assessment = VulnerabilityAssessmentManager(results_dir, simulation_name)
    
    try:
        # Load devices from ground truth
        assessment.load_devices()
        
        # Load scanner results to enhance IVSS scoring
        assessment.load_scanner_results()
        
        # Check if topology exists
        topology_path = os.path.join(results_dir, f"{simulation_name}_topology.png")
        if os.path.exists(topology_path):
            logger.info(f"Using existing topology visualization: {topology_path}")
        else:
            logger.warning(f"No topology visualization found at {topology_path}")

        num_scenarios = assessment.setup_scenarios(False)
        logger.info(f"Set up {num_scenarios} standard vulnerability scenarios")
        
        # Run assessment
        logger.info("Running vulnerability scenarios")
        assessment_results = assessment.run_assessment()
        
        # Always save assessment results to JSON
        assessment.save_assessment_results(assessment_results)
        
        # Prepare results for visualization
        comparator = assessment.prepare_for_visualization(assessment_results)
        
        # Generate and save key statistics
        stats_path = assessment.save_key_statistics(comparator)
        if stats_path:
            logger.info(f"Key statistics JSON saved to: {stats_path}")
        
        return assessment_results
        
    except Exception as e:
        logger.error(f"Error during vulnerability assessment: {e}", exc_info=True)
        return None
    
def setup_common_scenarios(self) -> int:
    """
    Set up common vulnerability scenarios for cross-network comparison.
    This method uses a fixed set of scenarios that work on both networks.
    
    Returns:
        Number of scenarios set up
    """
    self.logger.info("Setting up common vulnerability scenarios for cross-network comparison")
    
    # Clear any existing scenarios
    self.scenarios = []
    
    # These common scenarios should work across both network types
    # Make sure these vulnerabilities exist and are compatible with both networks
    common_scenarios = [
        "ModbusTCPRCEVulnerability",         # Works on both networks
        "SCADADenialOfServiceVulnerability", # Works on both networks
        "FirmwareUpdateVulnerability"        # Works on both networks
    ]
    
    # Add each common scenario
    for scenario_name in common_scenarios:
        try:
            # Import the vulnerability class
            module = importlib.import_module("vulnerabilities.common")
            vulnerability_class = getattr(module, scenario_name)
            
            # Create a descriptive name from the class name
            descriptive_name = re.sub(r'([a-z])([A-Z])', r'\1 \2', scenario_name.replace("Vulnerability", ""))
            
            # Add the CVE prefix if not already present
            if not descriptive_name.startswith("CVE-"):
                # You can define actual CVE numbers for each scenario here
                cve_mapping = {
                    "ModbusTCP RCE": "CVE-2020-14500",
                    "SCADA Denial Of Service": "CVE-2020-12033",
                    "Firmware Update": "CVE-2012-6437"
                }
                # Get the CVE number or use a placeholder
                cve = cve_mapping.get(descriptive_name, "CVE-XXXX-XXXX")
                descriptive_name = f"{cve}: {descriptive_name}"
                
            # Create the scenario
            self.logger.info(f"Adding scenario: {descriptive_name}")
            scenario = {
                "name": descriptive_name,
                "vulnerability": vulnerability_class(self.devices),
                "devices": self.devices
            }
            
            # Add to the list of scenarios
            self.scenarios.append(scenario)
            self.logger.info(f"Added scenario with {len(self.devices)} devices")
            self.logger.info(f"Added {scenario_name} to assessment")
            
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Failed to load vulnerability scenario {scenario_name}: {e}")
            continue
            
    return len(self.scenarios)

def run_complete_assessment(simulation_name: str, adjustment_method: str = "balanced") -> Tuple[bool, Optional[str]]:
    """
    Run a complete vulnerability assessment pipeline.
    """
    logger = setup_logging()
    logger.info(f"Starting complete vulnerability assessment for {simulation_name}")
    
    # Initialize the performance timer
    from utils.performance_timer import PerformanceTimer
    timer = PerformanceTimer()
    
    # Set environment variable for adjustment method
    os.environ["IVSS_ADJUSTMENT_METHOD"] = adjustment_method
    
    # Step 1: Run simulation
    logger.info("Running network simulation")
    timer.start("simulation")
    simulation_output, results_dir = run_simulation(simulation_name)
    simulation_time = timer.stop("simulation")
    logger.info(f"Simulation completed in {simulation_time:.2f} seconds")
    
    if not simulation_output or not results_dir:
        logger.error("Simulation failed. Exiting assessment.")
        return False, None
    
    # Step 2: Run scanner
    logger.info("Running network scanner")
    timer.start("network_scanning")
    comprehensive_file = run_network_scanner(
        simulation_output=simulation_output,
        results_dir=results_dir,
        simulation_name=simulation_name
    )
    scanning_time = timer.stop("network_scanning")
    logger.info(f"Network scanning completed in {scanning_time:.2f} seconds")
    
    if not comprehensive_file:
        logger.error("Network scanning failed to produce comprehensive results. Exiting assessment.")
        return False, None
    
    # Step 3: Run vulnerability assessment
    logger.info("Running vulnerability assessment")
    assessment_results = run_vulnerability_assessment(
        results_dir=results_dir,
        simulation_name=simulation_name,
        run_common_scenarios=False
    )
    
    if not assessment_results:
        logger.error("Vulnerability assessment failed.")
        return False, None
    
    # Log total execution time
    total_time = timer.get_total_time()
    logger.info(f"Total assessment time: {total_time:.2f} seconds")
    
    return True, results_dir

def extract_key_statistics_from_results(results_file):
    """
    Extract key statistics from an assessment_results.json file.
    
    Args:
        results_file: Path to assessment_results.json file
        
    Returns:
        Dictionary with key statistics
    """
    logger = logging.getLogger("StatsExtractor")
    logger.info(f"Extracting key statistics from {results_file}")
    
    # Load the assessment results
    try:
        with open(results_file, 'r') as f:
            assessment_results = json.load(f)
        
        logger.info(f"Loaded assessment results with {len(assessment_results)} vulnerabilities")
    except Exception as e:
        logger.error(f"Error loading assessment results: {e}")
        return None
    
    # Initialize statistics
    key_stats = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": len(assessment_results)
        },
        "average_scores": {
            "cvss": 0,
            "standalone_ivss": 0,
            "hybrid_ivss": 0
        },
        "average_differences": {
            "cvss_to_standalone": 0,
            "cvss_to_hybrid": 0,
            "standalone_to_hybrid": 0
        },
        "severity_shifts": {
            "cvss_to_standalone": {},
            "cvss_to_hybrid": {},
            "standalone_to_hybrid": {}
        },
        "vulnerabilities": []
    }
    
    # Extract data from each vulnerability
    total_cvss = 0
    total_ivss = 0
    total_hybrid = 0
    total_diff_cvss_ivss = 0
    total_diff_cvss_hybrid = 0
    total_diff_ivss_hybrid = 0
    
    # Process each vulnerability
    for vuln_id, vuln_data in assessment_results.items():
        # Get vulnerability data
        if "vulnerability_data" in vuln_data:
            vuln_info = vuln_data["vulnerability_data"]
            
            # Extract scores
            cvss_score = vuln_info.get("cvss_score", 0)
            ivss_score = vuln_info.get("standalone_ivss_score", 0)
            hybrid_score = vuln_info.get("hybrid_ivss_score", 0)
            
            # Accumulate scores for averages
            total_cvss += cvss_score
            total_ivss += ivss_score
            total_hybrid += hybrid_score
            
            # Accumulate differences
            diff_cvss_ivss = vuln_info.get("score_difference_cvss_ivss", 0)
            diff_cvss_hybrid = vuln_info.get("score_difference_cvss_hybrid", 0)
            diff_ivss_hybrid = vuln_info.get("score_difference_ivss_hybrid", 0)
            
            total_diff_cvss_ivss += diff_cvss_ivss
            total_diff_cvss_hybrid += diff_cvss_hybrid
            total_diff_ivss_hybrid += diff_ivss_hybrid
            
            # Track severity shifts
            shift_cvss_ivss = vuln_info.get("severity_shift_cvss_ivss", "No Change")
            shift_cvss_hybrid = vuln_info.get("severity_shift_cvss_hybrid", "No Change")
            shift_ivss_hybrid = vuln_info.get("severity_shift_ivss_hybrid", "No Change")
            
            key_stats["severity_shifts"]["cvss_to_standalone"][shift_cvss_ivss] = \
                key_stats["severity_shifts"]["cvss_to_standalone"].get(shift_cvss_ivss, 0) + 1
                
            key_stats["severity_shifts"]["cvss_to_hybrid"][shift_cvss_hybrid] = \
                key_stats["severity_shifts"]["cvss_to_hybrid"].get(shift_cvss_hybrid, 0) + 1
                
            key_stats["severity_shifts"]["standalone_to_hybrid"][shift_ivss_hybrid] = \
                key_stats["severity_shifts"]["standalone_to_hybrid"].get(shift_ivss_hybrid, 0) + 1
            
            # Add vulnerability to the list
            vuln_summary = {
                "id": vuln_id,
                "cve_id": vuln_info.get("cve_id", ""),
                "cvss_score": cvss_score,
                "ivss_score": ivss_score,
                "hybrid_score": hybrid_score,
                "affected_devices": len(vuln_data.get("affected_devices", {}))
            }
            
            key_stats["vulnerabilities"].append(vuln_summary)
    
    # Calculate averages
    num_vulns = len(assessment_results)
    if num_vulns > 0:
        key_stats["average_scores"]["cvss"] = total_cvss / num_vulns
        key_stats["average_scores"]["standalone_ivss"] = total_ivss / num_vulns
        key_stats["average_scores"]["hybrid_ivss"] = total_hybrid / num_vulns
        
        key_stats["average_differences"]["cvss_to_standalone"] = total_diff_cvss_ivss / num_vulns
        key_stats["average_differences"]["cvss_to_hybrid"] = total_diff_cvss_hybrid / num_vulns
        key_stats["average_differences"]["standalone_to_hybrid"] = total_diff_ivss_hybrid / num_vulns
    
    # Add severity distribution
    key_stats["severity_distribution"] = {
        "None": 0,
        "Low": 0,
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }
    
    # Count vulnerabilities by severity
    for vuln in key_stats["vulnerabilities"]:
        severity = get_severity_category(vuln["cvss_score"])
        key_stats["severity_distribution"][severity] += 1
    
    return key_stats

def get_severity_category(score):
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

def generate_combined_statistics(standard_dir, hidden_dir, combined_dir):
    """
    Generate combined statistics JSON from both standard and hidden network assessments.
    
    Args:
        standard_dir: Directory containing standard network results
        hidden_dir: Directory containing hidden/edge network results
        combined_dir: Directory to save combined statistics
        
    Returns:
        Path to the generated JSON file or None if failed
    """
    logger = logging.getLogger("CombinedStats")
    logger.info("Generating combined statistics from both network assessments")
    
    # Define paths to assessment result files
    standard_results = os.path.join(standard_dir, "assessment_results.json")
    hidden_results = os.path.join(hidden_dir, "assessment_results.json")
    
    # Extract statistics from both networks
    standard_stats = extract_key_statistics_from_results(standard_results) if os.path.exists(standard_results) else None
    hidden_stats = extract_key_statistics_from_results(hidden_results) if os.path.exists(hidden_results) else None
    
    if not standard_stats and not hidden_stats:
        logger.error("No valid assessment results found for either network")
        return None
    
    # Create combined statistics structure
    combined_stats = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "standard_network": bool(standard_stats),
            "edge_hidden_network": bool(hidden_stats),
            "total_vulnerabilities": {
                "standard": len(standard_stats.get("vulnerabilities", [])) if standard_stats else 0,
                "hidden": len(hidden_stats.get("vulnerabilities", [])) if hidden_stats else 0,
                "total": (len(standard_stats.get("vulnerabilities", [])) if standard_stats else 0) + 
                        (len(hidden_stats.get("vulnerabilities", [])) if hidden_stats else 0)
            }
        },
        "network_comparison": {
            "standard_network": {},
            "edge_hidden_network": {}
        },
        "scoring_comparison": {
            "cvss": {
                "standard_avg": standard_stats.get("average_scores", {}).get("cvss", 0) if standard_stats else 0,
                "hidden_avg": hidden_stats.get("average_scores", {}).get("cvss", 0) if hidden_stats else 0,
                "difference": abs((standard_stats.get("average_scores", {}).get("cvss", 0) if standard_stats else 0) - 
                                (hidden_stats.get("average_scores", {}).get("cvss", 0) if hidden_stats else 0))
            },
            "ivss": {
                "standard_avg": standard_stats.get("average_scores", {}).get("standalone_ivss", 0) if standard_stats else 0,
                "hidden_avg": hidden_stats.get("average_scores", {}).get("standalone_ivss", 0) if hidden_stats else 0,
                "difference": abs((standard_stats.get("average_scores", {}).get("standalone_ivss", 0) if standard_stats else 0) - 
                                (hidden_stats.get("average_scores", {}).get("standalone_ivss", 0) if hidden_stats else 0))
            },
            "hybrid": {
                "standard_avg": standard_stats.get("average_scores", {}).get("hybrid_ivss", 0) if standard_stats else 0,
                "hidden_avg": hidden_stats.get("average_scores", {}).get("hybrid_ivss", 0) if hidden_stats else 0,
                "difference": abs((standard_stats.get("average_scores", {}).get("hybrid_ivss", 0) if standard_stats else 0) - 
                                (hidden_stats.get("average_scores", {}).get("hybrid_ivss", 0) if hidden_stats else 0))
            }
        },
        "severity_distribution": {
            "standard_network": standard_stats.get("severity_distribution", {}) if standard_stats else {},
            "edge_hidden_network": hidden_stats.get("severity_distribution", {}) if hidden_stats else {}
        },
        "severity_shifts": {
            "standard_network": standard_stats.get("severity_shifts", {}) if standard_stats else {},
            "edge_hidden_network": hidden_stats.get("severity_shifts", {}) if hidden_stats else {}
        },
        "vulnerabilities": {
            "standard_network": standard_stats.get("vulnerabilities", []) if standard_stats else [],
            "edge_hidden_network": hidden_stats.get("vulnerabilities", []) if hidden_stats else []
        }
    }
    
    # Add network-specific statistics
    if standard_stats:
        combined_stats["network_comparison"]["standard_network"] = {
            "average_scores": standard_stats.get("average_scores", {}),
            "average_differences": standard_stats.get("average_differences", {})
        }
        
    if hidden_stats:
        combined_stats["network_comparison"]["edge_hidden_network"] = {
            "average_scores": hidden_stats.get("average_scores", {}),
            "average_differences": hidden_stats.get("average_differences", {})
        }
    
    # Calculate key insights about the differences between networks
    if standard_stats and hidden_stats:
        # Look at which scoring method shows the biggest difference between networks
        cvss_diff = combined_stats["scoring_comparison"]["cvss"]["difference"]
        ivss_diff = combined_stats["scoring_comparison"]["ivss"]["difference"]
        hybrid_diff = combined_stats["scoring_comparison"]["hybrid"]["difference"]
        
        combined_stats["key_insights"] = {
            "scoring_method_with_largest_network_difference": 
                "CVSS" if cvss_diff >= ivss_diff and cvss_diff >= hybrid_diff else
                "IVSS" if ivss_diff >= cvss_diff and ivss_diff >= hybrid_diff else
                "Hybrid",
            "scoring_method_with_smallest_network_difference":
                "CVSS" if cvss_diff <= ivss_diff and cvss_diff <= hybrid_diff else
                "IVSS" if ivss_diff <= cvss_diff and ivss_diff <= hybrid_diff else
                "Hybrid",
            "network_difference_magnitude": 
                "Large" if max(cvss_diff, ivss_diff, hybrid_diff) > 2.0 else
                "Medium" if max(cvss_diff, ivss_diff, hybrid_diff) > 1.0 else
                "Small"
        }
    
    # Save combined statistics
    output_file = os.path.join(combined_dir, "combined_statistics.json")
    
    try:
        with open(output_file, 'w') as f:
            json.dump(combined_stats, f, indent=2)
        logger.info(f"Combined statistics saved to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"Error saving combined statistics: {e}")
        return None

def run_all_simulations(adjustment_method: str = "balanced",
                       generate_individual_dashboards: bool = False,
                       generate_individual_reports: bool = False,
                       save_individual_visualizations: bool = False) -> bool:
    """
    Run both standard and edge/hidden vulnerability assessments with a streamlined directory structure.
    
    Args:
        adjustment_method: Method of adjustment for IVSS modifiers
        generate_individual_dashboards: Whether to generate individual dashboards for each network type
        generate_individual_reports: Whether to generate individual reports for each network type
        
    Returns:
        True if all assessments completed successfully, False otherwise
    """
    logger = setup_logging()
    
    # Start overall timer
    from utils.performance_timer import PerformanceTimer
    overall_timer = PerformanceTimer()

    os.environ["COMBINED_ASSESSMENT"] = "true"
    logger.info("Individual reports will NOT be generated (only combined report)")
    # Set environment variable for dashboard control
    if generate_individual_dashboards:
        if "GENERATE_INDIVIDUAL_DASHBOARDS" in os.environ:
            del os.environ["GENERATE_INDIVIDUAL_DASHBOARDS"]
        logger.info("Individual dashboards will be generated for each network type")
    else:
        os.environ["GENERATE_INDIVIDUAL_DASHBOARDS"] = "false"
        logger.info("Individual dashboards will NOT be generated (only combined dashboard)")
    

    # Create a single combined results directory with organized structure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_dir = os.path.join(os.path.dirname(__file__), "results", f"assessment_{timestamp}")
    
    # Create standard, hidden, and combined subdirectories
    standard_dir = os.path.join(combined_dir, "standard")
    hidden_dir = os.path.join(combined_dir, "hidden")
    combined_dir_output = os.path.join(combined_dir, "combined")
    
    os.makedirs(combined_dir, exist_ok=True)
    os.makedirs(standard_dir, exist_ok=True)
    os.makedirs(hidden_dir, exist_ok=True)
    os.makedirs(combined_dir_output, exist_ok=True)
    
    logger.info(f"Created assessment directory: {combined_dir}")
    
    for key in ["RESULTS_DIR", "SIM_PCAP_DIR", "IVSS_ADJUSTMENT_METHOD", "SIM_RANDOMIZE", "RANDOMIZED_MODE"]:
        logger.info(f"  {key}: {os.environ.get(key, 'Not set')}")
    
    # Check randomization settings
    sim_randomized = os.environ.get("SIM_RANDOMIZE", "").lower() in ["true", "1", "yes"]
    
    if sim_randomized:
        logger.info("Running with RANDOMIZED simulation (network and communication patterns)")
        if "SIM_SEED" in os.environ:
            logger.info(f"Using simulation seed: {os.environ['SIM_SEED']}")
    
    # Temporarily modify the results directory path to save standard assessment directly to standard_dir
    standard_success = False
    edge_success = False
    
    # Run standard network assessment directly to the standard directory
    logger.info("\n=== STARTING STANDARD NETWORK ASSESSMENT ===")
    try:
        old_path = os.path.join(os.path.dirname(__file__), "results")
        old_env = {}
        for key in ["RESULTS_DIR", "SIM_PCAP_DIR", "IVSS_ADJUSTMENT_METHOD"]:
            old_env[key] = os.environ.get(key)
        
        os.environ["RESULTS_DIR"] = standard_dir
    
        standard_success, _ = run_complete_assessment(
            simulation_name="standard_network",
            adjustment_method=adjustment_method
        )
        
        for key, value in old_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]
    except Exception as e:
        logger.error(f"Error during standard assessment: {e}")
        logger.info("DEBUG TRACEBACK:")
        import traceback
        logger.info(traceback.format_exc())
    
    # Run edge/hidden network assessment directly to the hidden directory
    logger.info("\n=== STARTING EDGE/HIDDEN NETWORK ASSESSMENT ===")
    try:
        old_env = {}
        for key in ["RESULTS_DIR", "SIM_PCAP_DIR", "IVSS_ADJUSTMENT_METHOD"]:
            old_env[key] = os.environ.get(key)
            
        os.environ["RESULTS_DIR"] = hidden_dir
        
        # Run the assessment with debugging
        edge_success, _ = run_complete_assessment(
            simulation_name="edge_hidden_network",
            adjustment_method=adjustment_method
        )

        for key, value in old_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]
    except Exception as e:
        logger.error(f"Error during edge/hidden assessment: {e}")
        logger.info("DEBUG TRACEBACK:")
        import traceback
        logger.info(traceback.format_exc())
    
    # Generate combineddashboard
    logger.info("\n=== GENERATING COMBINED VISUALIZATIONS ===")
    if standard_success or edge_success:  # Changed from 'and' to 'or' to be more permissive
        try:
            # Generate combined dashboard
            from utils.visualiser import generate_combined_dashboard
            dashboard_path = os.path.join(combined_dir_output, "combined_dashboard.png")

            stats_file = generate_combined_statistics(standard_dir, hidden_dir, combined_dir_output)
            if stats_file:
                logger.info(f"Generated combined statistics: {stats_file}")
                
                # Copy to root directory for easier access
                root_stats_file = os.path.join(combined_dir, "combined_statistics.json")
                shutil.copy2(stats_file, root_stats_file)
                logger.info(f"Copied combined statistics to root directory: {root_stats_file}")
            
            # Only generate the combined dashboard if both assessments were successful
            if standard_success and edge_success:
                generate_combined_dashboard(standard_dir, hidden_dir, dashboard_path, save_individual_visualizations)
                logger.info(f"Generated combined dashboard: {dashboard_path}")
            else:
                logger.info("Skipping combined dashboard generation because one assessment failed")
        except Exception as e:
            logger.error(f"Error generating combined dashboard: {e}")
            logger.info("DEBUG TRACEBACK:")
            import traceback
            logger.info(traceback.format_exc())


    # Clean up temporary files
    logger.info("\n=== CLEANING UP TEMPORARY FILES ===")

    try:
        cleanup_visualization_files(standard_dir, hidden_dir, combined_dir_output)
    except Exception as e:
        logger.error(f"Error during visualization cleanup: {e}")
    try:
        cleanup_temp_files(combined_dir)
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    
    logger.info("\n=== COMPLETE ASSESSMENT FINISHED ===")
    total_execution_time = overall_timer.get_total_time()
    logger.info(f"Total execution time: {total_execution_time:.2f} seconds")
    logger.info(f"Simulation randomization: {'ENABLED' if sim_randomized else 'DISABLED'}")
    if sim_randomized and os.environ.get('SIM_SEED'):
        logger.info(f"Simulation seed: {os.environ.get('SIM_SEED')}")
    logger.info(f"Standard network assessment: {'SUCCESS' if standard_success else 'FAILED'}")
    logger.info(f"Edge/hidden network assessment: {'SUCCESS' if edge_success else 'FAILED'}")
    logger.info(f"Results available in: {combined_dir}")
    logger.info("="*80)
    
    return standard_success and edge_success

def cleanup_temp_files(combined_dir: str) -> None:
    """
    Clean up temporary files in the assessment directory.
    
    This function removes any files that exist at the root level of the assessment
    directory but should be in one of the organized subdirectories.
    
    Args:
        combined_dir: Path to the combined assessment directory
    """
    logger = logging.getLogger("Cleanup")
    logger.info("Cleaning up temporary files in assessment directory")
    
    # Get a list of all files in the combined_dir
    all_items = os.listdir(combined_dir)
    
    # These are the directories we want to keep
    valid_dirs = ["comparison", "combined", "hidden", "standard"]
    
    # Go through each item
    for item in all_items:
        item_path = os.path.join(combined_dir, item)
        
        # If it's a directory and not one of our valid directories, or if it's a file
        if (os.path.isdir(item_path) and item not in valid_dirs) or (os.path.isfile(item_path) and not os.path.isdir(item_path)):
            try:
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    logger.info(f"Removed directory: {item}")
                else:
                    os.remove(item_path)
                    logger.info(f"Removed file: {item}")
            except Exception as e:
                logger.error(f"Error removing {item}: {e}")
    
    logger.info("Cleanup completed successfully")

def generate_performance_visualization(benchmark_data, output_path):
    """
    Generate performance visualization from benchmark data.
    
    Args:
        benchmark_data: List of benchmark data points
        output_path: Path to save the visualization
    """
    import matplotlib.pyplot as plt
    import numpy as np
    
    # Skip if no data
    if not benchmark_data:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Get unique network types and variations
    network_types = sorted(set(d["network_type"] for d in benchmark_data))
    variations = sorted(set(d["variation"] for d in benchmark_data))
    
    # Create matrix of durations
    durations = np.zeros((len(network_types), len(variations)))
    
    for i, network in enumerate(network_types):
        for j, variation in enumerate(variations):
            matching = [d for d in benchmark_data 
                       if d["network_type"] == network and d["variation"] == variation and d["success"]]
            if matching:
                durations[i, j] = matching[0]["duration"]
    
    # Create bar chart
    x = np.arange(len(variations))
    width = 0.35 if len(network_types) == 2 else 0.25
    
    plt.subplot(2, 1, 1)
    
    for i, network in enumerate(network_types):
        offset = width * (i - (len(network_types) - 1) / 2)
        bars = plt.bar(x + offset, durations[i], width, 
                      label=network.replace('_', ' ').title())
        
        # Add duration labels
        for bar, duration in zip(bars, durations[i]):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                    f'{duration:.1f}s',
                    ha='center', va='bottom', rotation=0)
    
    plt.ylabel('Execution Time (seconds)')
    plt.title('Performance Comparison by Network Type and Adjustment Method')
    plt.xticks(x, [v.title() for v in variations])
    plt.legend()
    
    # Add second subplot for network type comparison
    plt.subplot(2, 1, 2)
    
    # Calculate average times per network type
    network_avgs = {}
    for network in network_types:
        matching = [d["duration"] for d in benchmark_data 
                   if d["network_type"] == network and d["success"]]
        if matching:
            network_avgs[network] = sum(matching) / len(matching)
    
    network_names = [n.replace('_', ' ').title() for n in network_avgs.keys()]
    network_times = list(network_avgs.values())
    
    bars = plt.bar(network_names, network_times, color='skyblue')
    
    # Add duration labels
    for bar, duration in zip(bars, network_times):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                f'{duration:.1f}s',
                ha='center', va='bottom', rotation=0)
    
    plt.ylabel('Average Execution Time (seconds)')
    plt.title('Average Performance by Network Type')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()

def run_network_comparison(adjustment_method: str = "balanced") -> bool:
    """
    Run both network simulations with common vulnerability scenarios for direct comparison.
    
    Args:
        adjustment_method: Method to use for IVSS modifiers
        
    Returns:
        True if comparison completed successfully, False otherwise
    """
    logger = setup_logging()
    logger.info("Running vulnerability assessments for network comparison")
    
    # Create combined results directory for comparison
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    combined_dir = os.path.join(os.path.dirname(__file__), "results", f"network_comparison_{timestamp}")
    
    # Create subdirectories
    standard_dir = os.path.join(combined_dir, "standard")
    hidden_dir = os.path.join(combined_dir, "hidden")
    comparison_dir = os.path.join(combined_dir, "comparison")
    
    # Create directories
    os.makedirs(standard_dir, exist_ok=True)
    os.makedirs(hidden_dir, exist_ok=True)
    os.makedirs(comparison_dir, exist_ok=True)
    
    # Set environment variables to control output
    os.environ["GENERATE_INDIVIDUAL_DASHBOARDS"] = "true"  # Generate dashboards
    os.environ["GENERATE_INDIVIDUAL_REPORTS"] = "false"    # Skip reports
    
    # Define a list of common vulnerability scenarios that work on both networks
    common_vulnerability_scenarios = [
        "ModbusTCPRCEVulnerability",
        "SCADADenialOfServiceVulnerability",
        "FirmwareUpdateVulnerability"
    ]
    
    try:
        # Run standard network simulation first
        logger.info("\n=== RUNNING STANDARD NETWORK SIMULATION ===")
        # Set up environment for standard network
        os.environ["RESULTS_DIR"] = standard_dir
        
        # Run the simulation and network scanner
        standard_sim_output, _ = run_simulation("standard_network")
        if not standard_sim_output:
            logger.error("Standard network simulation failed")
            return False
            
        # Run the network scanner
        standard_ground_truth = run_network_scanner(
            simulation_output=standard_sim_output,
            results_dir=standard_dir,
            simulation_name="standard_network",
            randomized=False
        )
        
        if not standard_ground_truth:
            logger.error("Standard network scanner failed")
            return False
            
        # Modify standard network configuration with common scenarios
        logger.info("\n=== RUNNING STANDARD NETWORK WITH COMMON SCENARIOS ===")
        modified_std_config = copy.deepcopy(SIMULATIONS["standard_network"])
        modified_std_config["scenarios"] = common_vulnerability_scenarios
        
        # Temporarily replace the config
        original_std_config = SIMULATIONS["standard_network"]
        SIMULATIONS["standard_network"] = modified_std_config
        
        # Run the vulnerability assessment
        standard_results = run_vulnerability_assessment(standard_dir, "standard_network")
        
        # Restore the original config
        SIMULATIONS["standard_network"] = original_std_config
        
        # Now run edge/hidden network simulation
        logger.info("\n=== RUNNING EDGE/HIDDEN NETWORK SIMULATION ===")
        # Set up environment for edge/hidden network
        os.environ["RESULTS_DIR"] = hidden_dir
        
        # Run the simulation and network scanner
        hidden_sim_output, _ = run_simulation("edge_hidden_network")
        if not hidden_sim_output:
            logger.error("Edge/hidden network simulation failed")
            return False
            
        # Run the network scanner
        hidden_ground_truth = run_network_scanner(
            simulation_output=hidden_sim_output,
            results_dir=hidden_dir,
            simulation_name="edge_hidden_network",
            randomized=False
        )
        
        if not hidden_ground_truth:
            logger.error("Edge/hidden network scanner failed")
            return False
        
        # Run edge/hidden network assessment with common scenarios
        logger.info("\n=== RUNNING EDGE/HIDDEN NETWORK WITH COMMON SCENARIOS ===")
        # Create a modified configuration for edge/hidden network with common scenarios
        modified_edge_config = copy.deepcopy(SIMULATIONS["edge_hidden_network"])
        modified_edge_config["scenarios"] = common_vulnerability_scenarios
        
        # Temporarily replace the config
        original_edge_config = SIMULATIONS["edge_hidden_network"]
        SIMULATIONS["edge_hidden_network"] = modified_edge_config
        
        # Run the assessment
        edge_results = run_vulnerability_assessment(hidden_dir, "edge_hidden_network")
        
        # Restore the original config
        SIMULATIONS["edge_hidden_network"] = original_edge_config
        
        # Generate visualizations only (no reports)
        logger.info("\n=== GENERATING VISUALIZATIONS ONLY ===")
        
        # Generate combined dashboard
        try:
            from utils.visualiser import generate_combined_dashboard
            combined_dashboard_path = os.path.join(comparison_dir, "combined_dashboard.png")
            generate_combined_dashboard(standard_dir, hidden_dir, combined_dashboard_path)
            logger.info(f"Generated combined dashboard: {combined_dashboard_path}")
        except Exception as e:
            logger.error(f"Error generating combined dashboard: {e}", exc_info=True)
            
        # Generate network comparison
        try:
            logger.info("\n=== GENERATING NETWORK COMPARISON ANALYSIS ===")
            from utils.network_comparison import generate_network_comparison
            
            comparison_viz_path = os.path.join(comparison_dir, "network_comparison")
            
            # Make sure the directory exists
            os.makedirs(os.path.dirname(comparison_viz_path), exist_ok=True)
            
            logger.info(f"Visualization path: {comparison_viz_path}")
            
            # Call the modified function that doesn't generate reports
            generate_network_comparison(standard_dir, hidden_dir, comparison_viz_path)
            
        except Exception as e:
            logger.error(f"Error generating network comparison: {e}", exc_info=True)
        
        stats_file = generate_combined_statistics(standard_dir, hidden_dir, combined_dir)
        if stats_file:
            logger.info(f"Generated combined statistics: {stats_file}")
            
            shutil.copy2(stats_file, os.path.join(combined_dir, "network_comparison_results.json"))
            logger.info(f"Copied comparison results to: {os.path.join(combined_dir, 'network_comparison_results.json')}")
        
        # Clean up visualization files but DON'T delete the comparison directory
        try:
            cleanup_visualization_files(standard_dir, hidden_dir, comparison_dir)
        except Exception as e:
            logger.error(f"Error during visualization cleanup: {e}")
        
        # Copy important visualization files to the root for easier access
        try:
            for file in os.listdir(comparison_dir):
                if file.endswith(".png"):  # Only copy visualization files, not reports
                    src = os.path.join(comparison_dir, file)
                    dst = os.path.join(combined_dir, file)
                    shutil.copy2(src, dst)
                    logger.info(f"Copied {file} to root directory for easier access")
        except Exception as e:
            logger.error(f"Error copying files: {e}")
        
        logger.info(f"Network comparison analysis completed. Results available in: {combined_dir}")
        logger.info(f"Comparison visualizations are in: {comparison_dir}")
        return True
        
    except Exception as e:
        logger.error(f"Error during network comparison: {e}", exc_info=True)
        return False
    
def run_sensitivity_analysis(adjustment_method: str = "balanced") -> bool:
    """
    Run a sensitivity analysis to evaluate how robust the scoring differences are.
    """
    logger = setup_logging()
    logger.info(f"Running sensitivity analysis with {adjustment_method} adjustment")
    
    # Initialize performance timer
    from utils.performance_timer import PerformanceTimer
    timer = PerformanceTimer()
    
    # Create results directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_dir = os.path.join(os.path.dirname(__file__), "results", 
                              f"sensitivity_analysis_{timestamp}")
    output_dir = os.path.join(analysis_dir, "analysis")
    
    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    # Network types to run
    network_types = ["standard_network", "edge_hidden_network"]
    
    # Parameter variations to test
    variations = [
        {"name": "baseline", "adjustment": adjustment_method},
        {"name": "conservative", "adjustment": "conservative"},
        {"name": "aggressive", "adjustment": "aggressive"},
    ]
    
    # Store results from each variation and network
    variation_results = {}
    performance_data = []
    
    # Store all vulnerability data for combined visualization
    combined_vulnerability_data = {}
    
    # Run each network type
    for network_type in network_types:
        logger.info(f"\n=== ANALYZING NETWORK TYPE: {network_type} ===")
        
        network_dir = os.path.join(output_dir, network_type)
        os.makedirs(network_dir, exist_ok=True)
        
        network_results = {}
        
        # Run each variation for this network type
        for variation in variations:
            variation_name = variation["name"]
            local_adjustment = variation["adjustment"]
            
            logger.info(f"\n=== RUNNING VARIATION: {variation_name} on {network_type} ===")
            
            # Create variation subdirectory
            var_dir = os.path.join(network_dir, variation_name)
            os.makedirs(var_dir, exist_ok=True)
            
            # Set environment variables for this variation
            os.environ["RESULTS_DIR"] = var_dir
            os.environ["IVSS_ADJUSTMENT_METHOD"] = local_adjustment
            
            # Start timing this variation
            phase_name = f"{network_type}_{variation_name}"
            timer.start(phase_name)
            
            # Run assessment with this variation
            success, _ = run_complete_assessment(
                simulation_name=network_type,
                adjustment_method=local_adjustment
            )
            
            # Stop timing and record performance
            duration = timer.stop(phase_name)
            logger.info(f"Completed {phase_name} in {duration:.2f} seconds")
            
            # Track performance data
            performance_data.append({
                "network_type": network_type,
                "variation": variation_name,
                "adjustment": local_adjustment,
                "duration": duration,
                "success": success
            })
            
            if not success:
                logger.error(f"Variation {variation_name} failed on {network_type}")
                continue
            
            # Store results path for this variation
            network_results[variation_name] = var_dir
            logger.info(f"Completed variation: {variation_name} on {network_type}")
        
        # Store results for this network
        variation_results[network_type] = network_results
        
        # Generate sensitivity analysis for this network type
        if len(network_results) > 1:
            logger.info(f"\n=== GENERATING SENSITIVITY ANALYSIS FOR {network_type} ===")
            
            try:
                from utils.sensitivity_analyser import generate_sensitivity_analysis
                
                analysis_charts = os.path.join(output_dir, f"{network_type}_sensitivity_charts.png")
                
                # Generate the sensitivity analysis visualization only
                analysis_data = generate_sensitivity_analysis(
                    variation_results=network_results,
                    output_charts=analysis_charts,
                    return_analysis=True
                )
                
                # Store vulnerability data for combined visualization
                if analysis_data:
                    combined_vulnerability_data[network_type] = analysis_data
                
                # Save analysis data to JSON
                if analysis_data:
                    analysis_json = os.path.join(output_dir, f"{network_type}_sensitivity_data.json")
                    with open(analysis_json, 'w') as f:
                        json.dump(analysis_data, f, indent=2)
                
                logger.info(f"Sensitivity analysis visualization for {network_type} saved to {analysis_charts}")
            except Exception as e:
                logger.error(f"Error generating sensitivity analysis for {network_type}: {e}", exc_info=True)
    
    # Generate combined visualization only (no report)
    if len(variation_results) > 1 and combined_vulnerability_data:
        logger.info("\n=== GENERATING COMBINED VISUALIZATION ===")
        
        try:
            # Save performance metrics JSON
            performance_json = os.path.join(output_dir, "performance_metrics.json")
            with open(performance_json, 'w') as f:
                json.dump(performance_data, f, indent=2)
            
            # Save combined vulnerability data
            combined_data_file = os.path.join(output_dir, "combined_vulnerability_data.json")
            with open(combined_data_file, 'w') as f:
                json.dump(combined_vulnerability_data, f, indent=2)
            
            # Create just the combined visualization
            combined_charts = os.path.join(output_dir, "combined_sensitivity_charts.png")
            
            # Create the combined visualization from the saved data file
            from utils.sensitivity_analyser import create_combined_visualization
            
            create_combined_visualization(combined_data_file, combined_charts)
            
            logger.info(f"Combined visualization saved to {combined_charts}")
            
            # Generate performance visualization
            perf_viz_path = os.path.join(output_dir, "performance_comparison.png")
            generate_performance_visualization(performance_data, perf_viz_path)
            logger.info(f"Performance visualization saved to {perf_viz_path}")
            
            return True
        except Exception as e:
            logger.error(f"Error generating visualizations: {e}", exc_info=True)
            return False
    else:
        logger.error("Insufficient network data for combined analysis")
        return False

def main():
    """Main entry point for the application."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Industrial Control System Vulnerability Scoring Comparison Tool"
    )
    
    parser.add_argument("--standard-only", action="store_true", default=False, 
                       help="Run only the standard network simulation")
                       
    parser.add_argument("--edge-only", action="store_true", default=False, 
                       help="Run only the edge/hidden network simulation")
                       
    parser.add_argument("--adjustment", type=str, default="balanced", 
                       choices=["balanced", "conservative", "aggressive"],
                       help="Adjustment strength for IVSS environmental modifiers")
    
    parser.add_argument("--individual-visualizations", action="store_true", default=False,
                 help="Save each visualization panel from the dashboard as separate files")
    
    parser.add_argument("--random-simulation", action="store_true", default=False,
                       help="Enable randomized network and communication patterns in the simulation")
    
    parser.add_argument("--seed", type=int, default=None,
                       help="Random seed for reproducible simulations (when randomization is enabled)")
    
    parser.add_argument("--common-scenarios", action="store_true", default=False,
                      help="Run the same vulnerability scenarios on both networks for comparison")
    
    parser.add_argument("--sensitivity-analysis", action="store_true", default=False,
                      help="Run multiple iterations with varying parameters to test scoring robustness")
                   
    parser.add_argument("--individual-dashboards", action="store_true", default=False,
                      help="Generate individual dashboards for each network type")
    
    # Removed the individual-reports argument
    
    args = parser.parse_args()
    
    # Handle adjustment method
    if args.adjustment:
        os.environ["IVSS_ADJUSTMENT_METHOD"] = args.adjustment
    
    
    if args.random_simulation:
        os.environ["SIM_RANDOMIZE"] = "true"
        if args.seed is not None:
            os.environ["SIM_SEED"] = str(args.seed)
    
    # Run requested simulation mode
    if args.common_scenarios:
        success = run_network_comparison(adjustment_method=args.adjustment)
        sys.exit(0 if success else 1)
    
    if args.sensitivity_analysis:
        success = run_sensitivity_analysis(adjustment_method=args.adjustment)
        sys.exit(0 if success else 1)
    
    if args.standard_only:
        # Run only standard network
        success, results_dir = run_complete_assessment(
            simulation_name="standard_network",
            adjustment_method=args.adjustment
        )
        sys.exit(0 if success else 1)
    
    if args.edge_only:
        # Run only edge/hidden network
        success, results_dir = run_complete_assessment(
            simulation_name="edge_hidden_network",
            adjustment_method=args.adjustment
        )
        sys.exit(0 if success else 1)
    
    # Default behavior: run all simulations
    success = run_all_simulations(
        adjustment_method=args.adjustment,
        generate_individual_dashboards=args.individual_dashboards,
        generate_individual_reports=False,  # Always set to False to skip reports
        save_individual_visualizations=args.individual_visualizations
    )
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()