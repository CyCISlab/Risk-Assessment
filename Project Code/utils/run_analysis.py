#!/usr/bin/env python3
"""
Vulnerability Assessment Manager

Manages the assessment of vulnerabilities across different simulation configurations.
Coordinates loading devices, running scenarios, and generating reports.
"""

import os
import sys
import logging
import json
import traceback
from datetime import datetime
from typing import List, Dict, Any, Optional
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanning.device import Device
from simulation.simulation_config import SIMULATIONS

class VulnerabilityAssessmentManager:
    """
    Manages vulnerability assessments across different simulation configurations.
    
    This class coordinates:
    - Loading device information from ground truth data
    - Setting up vulnerability scenarios based on simulation type
    - Running vulnerability assessments
    - Generating reports and visualizations
    """
    
    def __init__(self, results_dir: str, simulation_name: str = "standard_network"):
        """
        Initialize the assessment manager.
        
        Args:
            results_dir: Directory to store assessment results
            simulation_name: Type of simulation to use (from simulation_config)
        """
        self.results_dir = results_dir
        self.simulation_name = simulation_name
        self.simulation_config = SIMULATIONS[simulation_name]
        self.devices = []
        self.scenarios = []
        self.scanner_results = {}  # Added to store scanner results
        
        # Set up logging
        self._setup_logging()

    def load_devices(self) -> List[Device]:
        """
        Load devices from comprehensive results file.
        
        Returns:
            List of Device objects loaded from results
        
        Raises:
            FileNotFoundError: If comprehensive results file is not found
            ValueError: If file has invalid format
        """
        self.logger.info("Loading devices from comprehensive results file")
        
        # Clear existing devices list
        self.devices = []
        
        # Try the simulation-specific comprehensive results file first
        comprehensive_file = os.path.join(self.results_dir, f"{self.simulation_name}_comprehensive_results.json")
        
        # If not found, try with generic name
        if not os.path.exists(comprehensive_file):
            comprehensive_file = os.path.join(self.results_dir, "comprehensive_results.json")
        
        if not os.path.exists(comprehensive_file):
            self.logger.error(f"Comprehensive results file not found at {comprehensive_file}")
            raise FileNotFoundError(f"No comprehensive results file found in {self.results_dir}")
        
        # Load the comprehensive file
        try:
            with open(comprehensive_file, 'r') as f:
                results_data = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing comprehensive results file: {e}")
            raise ValueError(f"Invalid JSON in comprehensive results file: {e}")
        
        # Process the comprehensive data structure
        if "devices" in results_data:
            # Process each device
            for ip, device_info in results_data["devices"].items():
                # Get device information
                info = device_info.get("device_info", {})
                
                # Create Device object
                device = Device(
                    ip=ip,
                    device_type=info.get('type', 'Unknown'),
                    network=info.get('network', 'Unknown'),
                    hidden=info.get('hidden', False)
                )
                
                # Add detection information as attributes
                detection_info = device_info.get("detection_info", {})
                for key, value in detection_info.items():
                    if key != "pcap_hidden_device":  # Skip the large PCAP evidence
                        if isinstance(value, dict):
                            for subkey, subvalue in value.items():
                                device.add_attribute(f"{key}_{subkey}", subvalue)
                        else:
                            device.add_attribute(key, value)
                
                # Add connection information
                connections = device_info.get("connections", [])
                if connections:
                    device.add_attribute("connections", connections)
                
                self.devices.append(device)
                
            self.logger.info(f"Successfully loaded {len(self.devices)} devices from comprehensive results file")
            return self.devices
        else:
            self.logger.error("Comprehensive results file has invalid format, missing 'devices' section")
            raise ValueError("Invalid comprehensive results file format")
    
    def load_scanner_results(self) -> None:
        """
        Load scanner results to enhance vulnerability assessments.
        """
        # Look for the comprehensive scan results file
        comprehensive_file = os.path.join(self.results_dir, "comprehensive_scan_results.json")
        
        if os.path.exists(comprehensive_file):
            try:
                with open(comprehensive_file, 'r') as f:
                    results = json.load(f)
                
                # Clear existing scanner results
                self.scanner_results = {}
                
                # Process each device's results
                for ip, device_data in results.items():
                    # Create a dictionary of scanning results for this device
                    self.scanner_results[ip] = {
                        'active_scan_status': device_data.get('active_scan_status', 'Not Assessed'),
                        'passive_monitoring_status': device_data.get('passive_monitoring_status', 'Not Assessed'),
                        'specialized_discovery_status': device_data.get('specialized_discovery_status', 'Not Assessed')
                    }
                
                self.logger.info(f"Loaded comprehensive scan results for {len(self.scanner_results)} devices")
                
                # Apply scanner results to device objects
                self._apply_scanner_results_to_devices()
                
            except Exception as e:
                self.logger.error(f"Error loading comprehensive scan results: {e}")
                self.logger.error(f"DEBUG: Error traceback: {traceback.format_exc()}")
        else:
            self.logger.warning(f"Comprehensive scan results file not found: {comprehensive_file}")
            self.logger.info(f"DEBUG: Current working directory: {os.getcwd()}")
            self.logger.info(f"DEBUG: Results directory exists: {os.path.exists(self.results_dir)}")

    def save_key_statistics(self, comparator, results_dir=None):
        """
        Save key statistics from vulnerability assessment to JSON file.
        
        Args:
            comparator: VulnerabilityComparator with assessment data
            results_dir: Directory to save results (defaults to self.results_dir)
            
        Returns:
            Path to the saved JSON file
        """
        if results_dir is None:
            results_dir = self.results_dir
            
        self.logger.info("Generating key statistics JSON output")
        
        # Create the output filename
        stats_path = os.path.join(results_dir, "key_statistics.json")
        
        # Export the key statistics
        success = comparator.export_key_statistics_to_json(stats_path)
        
        if success:
            self.logger.info(f"Key statistics saved to {stats_path}")
            return stats_path
        else:
            self.logger.error("Failed to save key statistics")
            return None
    
    def load_simulation_metadata(self) -> dict:
        """
        Load simulation metadata if available.
        
        This method checks for the presence of simulation_metadata.json
        which is created when randomization is enabled.
        
        Returns:
            Dictionary containing simulation metadata
        """
        self.logger.info("Checking for simulation metadata")
        metadata_file = os.path.join(self.results_dir, "simulation_metadata.json")
        metadata = {}
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                self.logger.info(f"Loaded simulation metadata: {metadata}")
                
                # Store as attribute for use in reporting
                self.simulation_metadata = metadata
                
                # Log randomization information
                if metadata.get('randomised', False):
                    self.logger.info(f"Simulation was randomised with seed: {metadata.get('seed', 'unknown')}")
            except Exception as e:
                self.logger.warning(f"Error loading simulation metadata: {e}")
        else:
            self.logger.info("No simulation metadata found (deterministic simulation)")
            self.simulation_metadata = {"randomised": False}
        
        return metadata

    # Update to prepare_for_visualization method
    def prepare_for_visualization(self, results: Dict[str, Any]):
        """
        Prepare assessment results for visualization.
        
        Args:
            results: Dictionary of vulnerability assessment results
            
        Returns:
            VulnerabilityComparator object with prepared data
        """
        from utils.comparator import VulnerabilityComparator
        
        self.logger.info("Preparing assessment results for visualization")
        
        # Load simulation metadata if not already loaded
        if not hasattr(self, 'simulation_metadata'):
            self.load_simulation_metadata()
        
        # Create comparator instance
        comparator = VulnerabilityComparator()
        
        # Add simulation type to comparator metadata
        comparator.metadata = {
            "simulation_type": self.simulation_name,
            "simulation_description": self.simulation_config.get("description", ""),
            "assessment_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "scanner_results_applied": bool(self.scanner_results),  # Track if scanner results were used
            "randomised_simulation": getattr(self, 'simulation_metadata', {}).get('randomised', False),
            "simulation_seed": getattr(self, 'simulation_metadata', {}).get('seed', None)
        }
        
        # Process each scenario's results
        for scenario_name, scenario_results in results.items():
            if isinstance(scenario_results, dict) and "error" in scenario_results:
                self.logger.warning(f"Skipping scenario '{scenario_name}' due to error: {scenario_results['error']}")
                continue
            
            # Check if using new result structure with vulnerability_data
            if 'vulnerability_data' in scenario_results:
                self._add_vulnerability_to_comparator(comparator, scenario_name, scenario_results)
        
        return comparator

    def run_network_scanner(simulation_output: str, results_dir: str, 
                        simulation_name: str) -> Dict:
        """
        Run network scanner to discover devices and build ground truth.
        """
        logger = logging.getLogger("Scanner")
        logger.info(f"Starting network scanner with results_dir: {results_dir}")
        logger.info(f"Running network scanner for {simulation_name} simulation")
        
        # Run the scanner with direct execution
        from scanning.network_scanner import NetworkScanner
        
        try:
            # Set up environment variables
            os.environ["SCAN_RESULTS_DIR"] = results_dir
            os.environ["SIMULATION_TYPE"] = simulation_name
            
            # Save simulation output to a file
            output_file = os.path.join(results_dir, "simulation_output.txt")
            with open(output_file, 'w') as f:
                f.write(simulation_output)
            
            # Create scanner instance
            scanner = NetworkScanner(
                output_dir=results_dir,
                simulation_type=simulation_name
            )
                
            # Process simulation output
            scanner.parse_simulation_output(output_file)
            
            # Verify comprehensive scan files were created
            comprehensive_file = os.path.join(results_dir, f"{simulation_name}_comprehensive_results.json")
            
            if os.path.exists(comprehensive_file):
                logger.info(f"Scanner successfully created comprehensive results")
                return comprehensive_file
            else:
                logger.error("Comprehensive results file not found")
                return None
                
        except Exception as e:
            logger.error(f"Error running scanner: {e}")
            logger.error(f"DEBUG: Error traceback: {traceback.format_exc()}")
            return None
        
    def _apply_scanner_results_to_devices(self) -> None:
        """
        Apply loaded scanner results to device objects.
        """
        for device in self.devices:
            # Skip if no scanner results for this device
            if device.ip not in self.scanner_results:
                continue
                
            # Get scanner results for this device
            device_results = self.scanner_results[device.ip]
            
            # Apply each result to the device
            for key, value in device_results.items():
                device.add_attribute(key, value)
                
        self.logger.info(f"Applied scanner results to {len(self.scanner_results)} devices")
        
    def _setup_logging(self) -> None:
        """Configure logging for the assessment process."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()  # Console output
            ]
        )
        self.logger = logging.getLogger("VulnerabilityAssessment")
    
    def add_scenario(self, scenario) -> None:
        """
        Add a vulnerability scenario to the assessment.
        
        Args:
            scenario: VulnerabilityScenario object to add
        """
        self.logger.info(f"Adding scenario: {scenario.name}")
        
        # Add all loaded devices to scenario
        for device in self.devices:
            scenario.add_device(device)
        
        self.scenarios.append(scenario)
        self.logger.info(f"Added scenario with {len(self.devices)} devices")
    
    def setup_scenarios(self, run_common_scenarios=False) -> int:
        """
        Set up vulnerability scenarios appropriate for the current simulation.
        
        Args:
            run_common_scenarios: Whether to run common scenarios on both networks
            
        Returns:
            Number of scenarios added
        """
        # Import scenarios dynamically to avoid circular imports
        from scenarios.modbus_vulnerability import ModbusTCPRCEVulnerability
        from scenarios.scada_hmi_vulnerability import SpiderControlHMIVulnerability
        from scenarios.scada_dos_vulnerability import SCADADenialOfServiceVulnerability
        from scenarios.edge_gateway_vulnerability import EdgeGatewayBypassVulnerability
        from scenarios.firmware_update_vulnerability import FirmwareUpdateVulnerability
        from scenarios.proprietary_vulnerability import ProprietaryProtocolVulnerability
        
        # Scenario mapping - associates names with classes
        scenario_mapping = {
            # Standard network scenarios
            "SpiderControlHMIVulnerability": SpiderControlHMIVulnerability,
            "ModbusTCPRCEVulnerability": ModbusTCPRCEVulnerability,
            "SCADADenialOfServiceVulnerability": SCADADenialOfServiceVulnerability,
            
            # Edge/Hidden network scenarios
            "EdgeGatewayBypassVulnerability": EdgeGatewayBypassVulnerability,
            "FirmwareUpdateVulnerability": FirmwareUpdateVulnerability,
            "ProprietaryProtocolVulnerability": ProprietaryProtocolVulnerability
        }
        
        # Get list of scenarios to run
        scenario_names = []
        
        if run_common_scenarios:
            # Run the three "common" scenarios that can run on both networks
            self.logger.info("Using common scenarios for cross-network comparison")
            scenario_names = [
                "SpiderControlHMIVulnerability",
                "ModbusTCPRCEVulnerability",
                "SCADADenialOfServiceVulnerability"
            ]
        else:
            # Use the network-specific scenarios defined in the configuration
            scenario_names = self.simulation_config.get("scenarios", [])
            
            # If no scenarios are defined, use default based on simulation type
            if not scenario_names:
                if self.simulation_name == "standard_network":
                    scenario_names = [
                        "SpiderControlHMIVulnerability",
                        "ModbusTCPRCEVulnerability",
                        "SCADADenialOfServiceVulnerability"
                    ]
                elif self.simulation_name == "edge_hidden_network":
                    scenario_names = [
                        "EdgeGatewayBypassVulnerability",
                        "FirmwareUpdateVulnerability",
                        "ProprietaryProtocolVulnerability"
                    ]
        
        # Create and add each scenario
        for scenario_name in scenario_names:
            if scenario_name in scenario_mapping:
                scenario_class = scenario_mapping[scenario_name]
                self.add_scenario(scenario_class())
            else:
                self.logger.warning(f"Unknown scenario: {scenario_name}, skipping")
                
        return len(self.scenarios)


    def run_assessment(self) -> Dict[str, Any]:
        """
        Run all vulnerability scenarios and collect results.
        
        Returns:
            Dictionary mapping scenario names to assessment results
        """
        from utils.performance_timer import PerformanceTimer
        timer = PerformanceTimer()
        
        self.logger.info(f"Starting vulnerability assessment for {self.simulation_name}")
        
        # Log randomization settings
        randomised = getattr(self, 'simulation_metadata', {}).get('randomised', False)
        seed = getattr(self, 'simulation_metadata', {}).get('seed', 'not specified')
        
        self.logger.info(f"Simulation was {'randomised' if randomised else 'deterministic'}")
        if randomised:
            self.logger.info(f"Simulation seed: {seed}")
        
        assessment_results = {}
        
        for scenario in self.scenarios:
            self.logger.info(f"Running scenario: {scenario.name}")
            
            try:
                # Time each scenario
                timer.start(scenario.name)
                scenario.assess_vulnerability()
                scenario_time = timer.stop(scenario.name)
                
                assessment_results[scenario.name] = scenario.get_results()
                self.logger.info(f"Completed scenario: {scenario.name} in {scenario_time:.2f} seconds")
                
            except Exception as e:
                self.logger.error(f"Error during scenario execution: {e}", exc_info=True)
                assessment_results[scenario.name] = {"error": str(e)}
        
        total_time = timer.get_total_time()
        self.logger.info(f"Assessment completed in {total_time:.2f} seconds")
        
        return assessment_results
    
    def _add_vulnerability_to_comparator(self, comparator, scenario_name: str, scenario_results: Dict[str, Any]) -> None:
        """
        Add a vulnerability to the comparator from scenario results.
        
        Args:
            comparator: VulnerabilityComparator to add data to
            scenario_name: Name of the scenario
            scenario_results: Results from the scenario assessment
        """
        vuln_data = scenario_results['vulnerability_data']
        
        # Create a unique ID for the vulnerability
        vuln_id = f"{scenario_name.replace(' ', '_')}"
        
        # Add to comparator results directly
        comparator.results.append({
            "id": vuln_id,
            "description": scenario_name,
            "simulation": self.simulation_name,
            "cvss": {
                "score": vuln_data.get("cvss_score", 0),
                "probability": vuln_data.get("cvss_probability", 0),
                "impact": vuln_data.get("cvss_impact", 0),
                "risk": vuln_data.get("cvss_probability", 0) * vuln_data.get("cvss_impact", 0) / 10
            },
            "standalone_ivss": {
                "score": vuln_data.get("standalone_ivss_score", 0),
                "probability": vuln_data.get("standalone_ivss_probability", 0),
                "impact": vuln_data.get("standalone_ivss_impact", 0),
                "risk": vuln_data.get("standalone_ivss_probability", 0) * vuln_data.get("standalone_ivss_impact", 0) / 10
            },
            "hybrid_ivss": {
                "score": vuln_data.get("hybrid_ivss_score", 0),
                "probability": vuln_data.get("hybrid_ivss_probability", 0),
                "impact": vuln_data.get("hybrid_ivss_impact", 0),
                "risk": vuln_data.get("hybrid_ivss_probability", 0) * vuln_data.get("hybrid_ivss_impact", 0) / 10,
                "modifier_impact": vuln_data.get("modifier_impact", 0)
            },
            "comparison": {
                "cvss_ivss": {
                    "absolute_difference": vuln_data.get("score_difference_cvss_ivss", 0),
                    "percentage_difference": 0,  # Will be calculated later
                    "severity_shift": vuln_data.get("severity_shift_cvss_ivss", "None"),
                    "probability_difference": abs(vuln_data.get("cvss_probability", 0) - vuln_data.get("standalone_ivss_probability", 0)),
                    "impact_difference": abs(vuln_data.get("cvss_impact", 0) - vuln_data.get("standalone_ivss_impact", 0)),
                    "risk_difference": 0  # Will be calculated later
                },
                "cvss_hybrid": {
                    "absolute_difference": vuln_data.get("score_difference_cvss_hybrid", 0),
                    "percentage_difference": 0,  # Will be calculated later
                    "severity_shift": vuln_data.get("severity_shift_cvss_hybrid", "None"),
                    "probability_difference": abs(vuln_data.get("cvss_probability", 0) - vuln_data.get("hybrid_ivss_probability", 0)),
                    "impact_difference": abs(vuln_data.get("cvss_impact", 0) - vuln_data.get("hybrid_ivss_impact", 0)),
                    "risk_difference": 0  # Will be calculated later
                },
                "ivss_hybrid": {
                    "absolute_difference": vuln_data.get("score_difference_ivss_hybrid", 0),
                    "percentage_difference": 0,  # Will be calculated later
                    "severity_shift": vuln_data.get("severity_shift_ivss_hybrid", "None"),
                    "probability_difference": abs(vuln_data.get("standalone_ivss_probability", 0) - vuln_data.get("hybrid_ivss_probability", 0)),
                    "impact_difference": abs(vuln_data.get("standalone_ivss_impact", 0) - vuln_data.get("hybrid_ivss_impact", 0)),
                    "risk_difference": 0  # Will be calculated later
                },
                "affected_devices": len(scenario_results.get('affected_devices', {}))
            }
        })
        
        self._calculate_comparator_percentages(comparator.results[-1])
        
        self.logger.info(f"Prepared scenario '{scenario_name}' for visualization")
    
    def _calculate_comparator_percentages(self, result: Dict[str, Any]) -> None:
        """
        Calculate percentage differences and risk differences for a comparator result.
        
        Args:
            result: Comparator result dictionary to update
        """
        # CVSS vs IVSS
        cvss_score = result["cvss"]["score"]
        ivss_score = result["standalone_ivss"]["score"]
        max_score = max(cvss_score, ivss_score)
        
        if max_score > 0:
            result["comparison"]["cvss_ivss"]["percentage_difference"] = (abs(cvss_score - ivss_score) / max_score) * 100
        
        cvss_risk = result["cvss"]["risk"]
        ivss_risk = result["standalone_ivss"]["risk"]
        result["comparison"]["cvss_ivss"]["risk_difference"] = abs(cvss_risk - ivss_risk)
        
        # CVSS vs Hybrid
        hybrid_score = result["hybrid_ivss"]["score"]
        max_score = max(cvss_score, hybrid_score)
        
        if max_score > 0:
            result["comparison"]["cvss_hybrid"]["percentage_difference"] = (abs(cvss_score - hybrid_score) / max_score) * 100
        
        hybrid_risk = result["hybrid_ivss"]["risk"]
        result["comparison"]["cvss_hybrid"]["risk_difference"] = abs(cvss_risk - hybrid_risk)
        
        # IVSS vs Hybrid
        max_score = max(ivss_score, hybrid_score)
        
        if max_score > 0:
            result["comparison"]["ivss_hybrid"]["percentage_difference"] = (abs(ivss_score - hybrid_score) / max_score) * 100
        
        result["comparison"]["ivss_hybrid"]["risk_difference"] = abs(ivss_risk - hybrid_risk)
    
    def save_assessment_results(self, results: Dict[str, Any]) -> str:
        """
        Save assessment results to JSON file, even when reports are disabled.
        
        Args:
            results: Vulnerability assessment results
            
        Returns:
            Path to the saved JSON file
        """
        self.logger.info("Saving assessment results to JSON")
        
        # Save complete technical data as JSON
        json_path = os.path.join(self.results_dir, "assessment_results.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Assessment results saved to {json_path}")
        return json_path
    
    def generate_dashboard(self, comparator, save_path: Optional[str] = None) -> Optional[str]:
        """
        Generate visualization dashboard.
        
        Args:
            comparator: VulnerabilityComparator with prepared data
            save_path: Optional path to save the visualization
            
        Returns:
            Path to the generated dashboard or None if an error occurred
        """
        from utils.visualiser import VulnerabilityVisualisation
        
        # By default, don't generate individual dashboards unless explicitly requested
        # Check if individual dashboards should be generated
        if os.environ.get("GENERATE_INDIVIDUAL_DASHBOARDS", "").lower() != "true":
            self.logger.info("Skipping individual dashboard generation (individual dashboards not enabled)")
            return None
        
        # Use provided save_path or default to results directory
        if save_path is None:
            save_path = os.path.join(self.results_dir, "vulnerability_dashboard.png")
        
        self.logger.info(f"Generating individual vulnerability dashboard at {save_path}")
        
        try:
            # Create visualization instance with our comparator
            viz = VulnerabilityVisualisation(comparator)
            
            # Generate comprehensive dashboard
            viz.create_dashboard(save_path=save_path)
            
            self.logger.info(f"Individual dashboard generated successfully: {save_path}")
            return save_path
            
        except Exception as e:
            self.logger.error(f"Error generating dashboard: {e}", exc_info=True)
            return None