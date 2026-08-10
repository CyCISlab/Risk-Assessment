"""
Simulation Helpers for ICS Simulations

Provides utility functions for ICS network simulations.
"""

import os
from datetime import datetime
import traceback
import sys

def setup_pcap_directory(env_var_name: str = "SIM_PCAP_DIR", fallback_path: str = None) -> str:
    """
    Set up a directory for packet captures.
    
    Args:
        env_var_name: Name of environment variable with directory path
        fallback_path: Fallback path if environment variable not set
        
    Returns:
        Path to PCAP directory
    """
    # Check environment variable
    pcap_dir = os.environ.get(env_var_name)
    
    if pcap_dir and os.path.exists(pcap_dir):
        print(f"Using provided PCAP directory: {pcap_dir}")
        return pcap_dir
    
    # Create fallback directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if fallback_path:
        base_dir = fallback_path
    else:
        # Default to current directory
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    
    results_dir = os.path.join(base_dir, "results", f"run_{timestamp}")
    pcap_dir = os.path.join(results_dir, "pcap")
    
    try:
        os.makedirs(pcap_dir, exist_ok=True)
        print(f"Created PCAP directory: {pcap_dir}")
        return pcap_dir
    except Exception as e:
        print(f"Warning: Failed to create PCAP directory: {e}")
        return None

def print_network_addresses(interface_dict: dict) -> None:
    """
    Print network addresses of all interfaces.
    
    Args:
        interface_dict: Dictionary mapping interface names to addresses
    """
    print("\nNetwork Addresses:")
    
    for segment, interfaces in interface_dict.items():
        print(f"\n{segment.upper()}:")
        for device, address in interfaces.items():
            print(f"{device}: {address}")

def run_simulation_safely(ns, simulation_time: float) -> bool:
    """
    Run the NS3 simulation with error handling.
    
    Args:
        ns: NS3 module
        simulation_time: Simulation duration in seconds
        
    Returns:
        True if simulation completed successfully, False otherwise
    """
    try:
        print(f"\nStarting simulation for {simulation_time} seconds")
        ns.Simulator.Stop(ns.Seconds(simulation_time))
        ns.Simulator.Run()
        ns.Simulator.Destroy()
        print("Simulation complete")
        return True
    except Exception as e:
        print(f"ERROR: Simulation failed with exception: {e}")
        print("Detailed traceback:")
        traceback.print_exc()
        return False