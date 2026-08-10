#!/usr/bin/env python3
"""
Industrial Control System Simulation - Standard Network

Simulates standard ICS network with typical components and communication patterns.
"""

try:
    from ns import ns
except ModuleNotFoundError:
    raise SystemExit(
        "Error: ns3 Python module not found;"
        " Python bindings may not be enabled"
        " or your PYTHONPATH might not be properly configured"
    )
import sys
import os
import random
from datetime import datetime
from ctypes import c_bool, c_int
import traceback
import json

# Import project modules
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
from simulation.simulation_config import SIMULATIONS
from simulation.network_builder import NetworkBuilder
from simulation.device_manager import DeviceManager
from simulation.application_manager import ApplicationManager
from utils.simulation_helpers import setup_pcap_directory, print_network_addresses, run_simulation_safely

def get_environment_settings() -> dict:
    """Get environment variables for simulation configuration."""
    env_randomize = os.environ.get("SIM_RANDOMIZE", "").lower()
    seed = os.environ.get("SIM_SEED")
    
    settings = {
        "randomize": env_randomize in ["true", "1", "yes"],
        "seed": int(seed) if seed else None
    }
    
    return settings

def create_simulation_nodes(network_builder, config: dict) -> dict:
    """Create all network nodes for simulation."""
    nodes = {}
    
    nodes["it"] = network_builder.create_nodes("itNodes", config["network"]["it_nodes"])
    nodes["dmz"] = network_builder.create_nodes("dmzNodes", config["network"]["dmz_nodes"])
    nodes["control"] = network_builder.create_nodes("otControlNodes", config["network"]["ot_control_nodes"])
    nodes["process"] = network_builder.create_nodes("otProcessNodes", config["network"]["ot_process_nodes"])
    nodes["maintenance"] = network_builder.create_nodes("maintenanceNodes", config["network"]["maintenance_nodes"])
    
    return nodes

def create_network_connections(network_builder) -> dict:
    """Create all network connections."""
    connections = {}
    
    # Point-to-point links
    connections["p2p_it_to_dmz"] = network_builder.create_p2p_link(
        "ItToDmz", "itNodes", 0, "dmzNodes", 0)
        
    connections["p2p_dmz_to_ot"] = network_builder.create_p2p_link(
        "DmzToOt", "dmzNodes", 0, "otControlNodes", 0)
        
    connections["p2p_control_to_process"] = network_builder.create_p2p_link(
        "ControlToProcess", "otControlNodes", 4, "otProcessNodes", 0)
        
    connections["p2p_control_to_maintenance"] = network_builder.create_p2p_link(
        "ControlToMaintenance", "otControlNodes", 2, "maintenanceNodes", 0)
    
    # CSMA networks
    connections["csma_control"] = network_builder.create_csma_network(
        "control", "otControlNodes", "100Mbps", 6560)
        
    connections["csma_process"] = network_builder.create_csma_network(
        "process", "otProcessNodes", "10Mbps", 10000)
    
    return connections

def assign_ip_addresses(network_builder, connections: dict) -> dict:
    """Assign IP addresses to all interfaces."""
    interfaces = {}
    
    interfaces["dmz"] = network_builder.assign_ip_addresses(
        "dmz", connections["p2p_it_to_dmz"][1], "10.1.2.0")
        
    interfaces["dmz_to_ot"] = network_builder.assign_ip_addresses(
        "dmzToOt", connections["p2p_dmz_to_ot"][1], "10.1.3.0")
        
    interfaces["control"] = network_builder.assign_ip_addresses(
        "otControl", connections["csma_control"], "192.168.1.0")
        
    interfaces["control_to_process"] = network_builder.assign_ip_addresses(
        "controlToProcess", connections["p2p_control_to_process"][1], "192.168.10.0")
        
    interfaces["process"] = network_builder.assign_ip_addresses(
        "otProcess", connections["csma_process"], "192.168.2.0")
        
    interfaces["maintenance"] = network_builder.assign_ip_addresses(
        "maintenance", connections["p2p_control_to_maintenance"][1], "192.168.100.0")
    
    return interfaces

def enable_topology_visualization(ns, network_builder, output_file=None):
    """
    Enable NS3's built-in topology visualization.
    
    Args:
        ns: NS3 module instance
        network_builder: Your NetworkBuilder instance
        output_file: Path to save the visualization output
    
    Returns:
        The animation interface object
    """
    # Create the animation interface - this generates an XML file that can be viewed with NetAnim
    output_path = output_file if output_file else "network-animation.xml"
    anim = ns.AnimationInterface(output_path)
    
    # Configure visualization parameters
    anim.EnablePacketMetadata(True)
    
    # Set node positions for better visualization
    for container_name, container in network_builder.node_containers.items():
        y_pos = 0
        if "it" in container_name.lower():
            y_pos = 80 
        elif "dmz" in container_name.lower():
            y_pos = 60
        elif "control" in container_name.lower():
            y_pos = 40
        elif "process" in container_name.lower():
            y_pos = 20
        elif "maintenance" in container_name.lower():
            y_pos = 10
            
        # Place nodes in a row
        for i in range(container.GetN()):
            anim.SetConstantPosition(container.Get(i), 10 + (i * 20), y_pos)
    
    # Additional options for NetAnim
    anim.EnableIpv4RouteTracking("ipv4-routing-table", 0, 10, 5)
    anim.EnableWifiMacCounters(0, 10)
    anim.EnableWifiPhyCounters(0, 10)
    
    return anim

def save_simulation_metadata(results_dir: str, randomize: bool, seed: int, simulation_time: int) -> None:
    """Save simulation metadata to JSON file."""
    metadata_file = os.path.join(results_dir, "simulation_metadata.json")
    metadata = {
        "simulation_type": "standard_network",
        "randomized": randomize,
        "seed": seed,
        "time": simulation_time,
        "timestamp": datetime.now().isoformat()
    }
    
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)

def run_standard_simulation() -> bool:
    """Run standard ICS network simulation."""
    try:
        # Get environment settings (all configuration is through environment variables)
        env_settings = get_environment_settings()
        randomize = env_settings["randomize"]
        seed = env_settings["seed"]
        
        # Generate seed if randomizing without explicit seed
        if randomize and seed is None:
            seed = random.randint(1, 10000)
        
        # Get simulation configuration
        sim_config = SIMULATIONS["standard_network"]

        # Setup NS3 parameters (use fixed values suitable for simulation)
        verbose = c_bool(True)
        tracing = c_bool(True)
        simulation_time = c_int(300)

        # Simple command line setup (no arguments needed)
        cmd = ns.CommandLine(__file__)
        cmd.Parse([""])

        if verbose.value:
            ns.LogComponentEnable("UdpEchoClientApplication", ns.LOG_LEVEL_INFO)
            ns.LogComponentEnable("UdpEchoServerApplication", ns.LOG_LEVEL_INFO)

        # Create managers
        network_builder = NetworkBuilder(ns, randomize=randomize, seed=seed)
        device_manager = DeviceManager(ns, network_builder, randomize=randomize, seed=seed)
        app_manager = ApplicationManager(ns, device_manager)
        
        # Register protocol ports
        app_manager.register_protocol_ports(sim_config["protocols"])

        # Create network components
        nodes = create_simulation_nodes(network_builder, sim_config)
        connections = create_network_connections(network_builder)
        
        # Install internet stack
        stack = ns.InternetStackHelper()
        for node_group in nodes.values():
            stack.Install(node_group)

        # Assign IP addresses
        interfaces = assign_ip_addresses(network_builder, connections)

        # Get important addresses
        addresses = {
            "serial_device": network_builder.get_interface_address("otProcess", 2),
            "hidden_backup": network_builder.get_interface_address("otProcess", 3)
        }

        # Setup applications
        app_manager.setup_standard_control_network(simulation_time.value)
        app_manager.setup_hidden_process_devices(
            simulation_time.value, 
            addresses["serial_device"], 
            addresses["hidden_backup"]
        )

        # Enable routing
        ns.Ipv4GlobalRoutingHelper.PopulateRoutingTables()
        
        # Create animation interface
        results_dir = os.environ.get("RESULTS_DIR", ".")
        anim_file = os.path.join(results_dir, "standard_animation.xml")
        anim = enable_topology_visualization(ns, network_builder, anim_file)
        
        # Add colors and labels (AFTER topology visualization)
        anim.UpdateNodeColor(0, 255, 0, 0)  # Red
        anim.UpdateNodeDescription(0, "Gateway")
        
        # Enable packet capture if tracing enabled
        if tracing.value:
            pcap_dir = setup_pcap_directory()
            if pcap_dir:
                network_builder.enable_pcap(pcap_dir)

        # Print network information
        print_network_addresses({
            "DMZ NETWORK": {
                "Router (DMZ)": network_builder.get_interface_address("dmz", 0),
                "SCADA (DMZ)": network_builder.get_interface_address("dmz", 1)
            },
            "OT CONTROL NETWORK": {
                "SCADA (OT)": network_builder.get_interface_address("dmzToOt", 1),
                "HMI": network_builder.get_interface_address("otControl", 0),
                "EWS": network_builder.get_interface_address("otControl", 1),
                "PLC1": network_builder.get_interface_address("otControl", 2),
                "PLC2": network_builder.get_interface_address("otControl", 3),
                "PLC3": network_builder.get_interface_address("otControl", 4)
            },
            "OT PROCESS NETWORK": {
                "Legacy PLC": network_builder.get_interface_address("otProcess", 0),
                "Silent Sensor": network_builder.get_interface_address("otProcess", 1),
                "Serial Device": addresses["serial_device"],
                "Hidden Backup": addresses["hidden_backup"]
            },
            "MAINTENANCE CONNECTION": {
                "PLC1 (Maint)": network_builder.get_interface_address("maintenance", 0),
                "Maintenance Interface": network_builder.get_interface_address("maintenance", 1)
            }
        })
        
        device_manager.print_device_summary()

        # Save metadata if randomized
        if randomize:
            results_dir = os.environ.get("RESULTS_DIR", ".")
            save_simulation_metadata(results_dir, randomize, seed, simulation_time.value)

        # Run simulation
        return run_simulation_safely(ns, simulation_time.value)
        
    except Exception as e:
        print(f"ERROR: Simulation failed with exception: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_standard_simulation()
    sys.exit(0 if success else 1)