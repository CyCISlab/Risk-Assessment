#!/usr/bin/env python3
"""
Network Topology Visualisation

Generates visual representations of industrial control system networks
with clear differentiation between network zones and device types.
"""

import os
import logging
import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, List, Optional, Tuple, Union

def generate_network_topology(devices: Union[List, Dict], 
                           connections: Optional[Dict[str, List[str]]] = None,
                           save_path: str = "network_topology.png", 
                           simulation_type: Optional[str] = None) -> str:
    """
    Generate a network topology visualisation from device data.
    
    Args:
        devices: List of Device objects or dictionary of device data
        connections: Dictionary mapping source IPs to lists of target IPs
        save_path: Path to save the visualisation image
        simulation_type: Type of simulation for customising the visualisation
        
    Returns:
        Path to the saved visualisation image
    """
    logger = logging.getLogger("NetworkTopology")
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(save_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    if connections is None:
        connections = {}
    
    # Create a directed graph
    G = nx.DiGraph()
    
    # Define network zones and their vertical positions
    network_zones = _get_network_zones(simulation_type)
    
    # Track devices by network for positioning
    devices_by_network = {network: [] for network in network_zones}
    
    # Add nodes to the graph
    node_count = _add_nodes_to_graph(G, devices, devices_by_network, network_zones, simulation_type)
    
    # Add edges to the graph
    edge_count = _add_edges_to_graph(G, connections)
    
    # Calculate node positions
    pos = _calculate_node_positions(devices_by_network, network_zones)
    
    # Set up node styling attributes
    node_colors, node_sizes, node_borders, border_widths = _get_node_styling(G, simulation_type)
    
    # Create the visualisation
    _create_visualisation(G, pos, node_colors, node_sizes, node_borders, border_widths, 
                        network_zones, save_path, simulation_type)
    
    return save_path

def _get_network_zones(simulation_type: Optional[str]) -> Dict[str, float]:
    """Get network zones and their vertical positions based on simulation type."""
    if simulation_type == "edge_hidden_network":
        return {
            "IT": 0.9, "IT NETWORK": 0.9,
            "DMZ": 0.75, "DMZ NETWORK": 0.75,
            "Edge": 0.6, "EDGE NETWORK": 0.6,
            "OT": 0.45, "CONTROL": 0.45, "CONTROL NETWORK": 0.45, "OT CONTROL NETWORK": 0.45,
            "Maintenance": 0.3, "MAINTENANCE NETWORK": 0.3,
            "Field": 0.15, "PROCESS": 0.15, "PROCESS NETWORK": 0.15, "OT PROCESS NETWORK": 0.15,
            "Hidden": 0.05, "Unknown": 0.01
        }
    else:
        return {
            "IT": 0.9, "IT NETWORK": 0.9,
            "DMZ": 0.7, "DMZ NETWORK": 0.7,
            "OT": 0.5, "CONTROL": 0.5, "CONTROL NETWORK": 0.5, "OT CONTROL NETWORK": 0.5,
            "PROCESS": 0.3, "PROCESS NETWORK": 0.3, "OT PROCESS NETWORK": 0.3,
            "Maintenance": 0.3, "MAINTENANCE NETWORK": 0.3,
            "Field": 0.1, "Unknown": 0.01
        }

def _add_nodes_to_graph(G: nx.DiGraph, devices: Union[List, Dict], 
                      devices_by_network: Dict[str, List[str]],
                      network_zones: Dict[str, float],
                      simulation_type: Optional[str]) -> int:
    """Add nodes to the graph based on device information."""
    # Check for comprehensive results format
    if isinstance(devices, dict) and "devices" in devices:
        devices = devices["devices"]
    
    node_count = 0
    
    # Process dictionary of devices
    if isinstance(devices, dict):
        for ip, device in devices.items():
            # Check if using comprehensive format (device_info nested inside)
            if isinstance(device, dict) and "device_info" in device:
                device_info = device["device_info"]
                is_hidden = device_info.get('hidden', False)
                device_type = device_info.get('type', 'Unknown')
                network = device_info.get('network', 'Unknown')
            else:
                is_hidden = device.get('hidden', False)
                device_type = device.get('type', 'Unknown')
                network = device.get('network', 'Unknown')
            
            # Skip if network not in network zones
            if network not in network_zones:
                continue
            
            # Add node with attributes
            G.add_node(ip, type=device_type, network=network, 
                    hidden=is_hidden, simulation=simulation_type)
            
            # Track devices by network zone
            if network in devices_by_network:
                devices_by_network[network].append(ip)
            
            node_count += 1
    
    # Process list of Device objects
    elif isinstance(devices, list):
        for device in devices:
            # Extract device info
            if hasattr(device, 'ip'):
                ip = device.ip
                device_type = getattr(device, 'device_type', getattr(device, 'type', 'Unknown'))
                network = getattr(device, 'network', 'Unknown')
                is_hidden = getattr(device, 'hidden', False)
            elif isinstance(device, dict):
                ip = device.get('ip', device.get('__index__', 'unknown'))
                device_type = device.get('type', 'Unknown')
                network = device.get('network', 'Unknown')
                is_hidden = device.get('hidden', False)
            else:
                continue
            
            # Skip if network not in network zones
            if network not in network_zones:
                continue
            
            # Add node with attributes
            G.add_node(ip, type=device_type, network=network, 
                    hidden=is_hidden, simulation=simulation_type)
            
            # Track devices by network zone
            if network in devices_by_network:
                devices_by_network[network].append(ip)
            
            node_count += 1
    
    return node_count

def _add_edges_to_graph(G: nx.DiGraph, connections: Dict[str, List[str]]) -> int:
    """Add edges to the graph based on connection information."""
    edge_count = 0
    
    if not connections:
        return 0
    
    # Process connections
    for source, targets in connections.items():
        if not targets:
            continue
        
        # Handle different connection formats
        if isinstance(targets, list):
            # Check if this is a list of strings or a list of dictionaries
            if targets and isinstance(targets[0], dict) and "target" in targets[0]:
                # List of connection dictionaries (new format)
                for conn in targets:
                    target = conn.get("target")
                    if source in G.nodes and target in G.nodes:
                        G.add_edge(source, target)
                        edge_count += 1
            else:
                # Simple list of target IPs (old format)
                for target in targets:
                    if source in G.nodes and target in G.nodes:
                        G.add_edge(source, target)
                        edge_count += 1
    
    return edge_count

def _calculate_node_positions(devices_by_network: Dict[str, List[str]], 
                            network_zones: Dict[str, float]) -> Dict[str, Tuple[float, float]]:
    """Calculate positions for nodes based on network zones."""
    pos = {}
    
    for network, devices in devices_by_network.items():
        if not devices:
            continue
            
        y_pos = network_zones[network]
        
        # Spread devices horizontally with more space
        if len(devices) > 1:
            # Calculate horizontal spacing based on number of devices
            spacing = min(0.8 / len(devices), 0.2)  # Cap maximum spacing
            start_x = 0.1
            end_x = 0.9
            
            # Adjust range to prevent devices from being too close to edges
            usable_width = end_x - start_x
            total_device_width = spacing * (len(devices) - 1)
            
            # Centre the devices horizontally
            if total_device_width < usable_width:
                start_x = 0.5 - (total_device_width / 2)
            
            for i, ip in enumerate(devices):
                x_pos = start_x + (i * spacing)
                pos[ip] = (x_pos, y_pos)
        else:
            # Centre single device
            pos[devices[0]] = (0.5, y_pos)
    
    return pos

def _get_node_styling(G: nx.DiGraph, simulation_type: Optional[str]) -> Tuple[List, List, List, List]:
    """Get styling information for nodes based on device types."""
    node_colors = []
    node_sizes = []
    node_borders = []
    border_widths = []
    
    for node in G.nodes():
        device_type = G.nodes[node]['type'].lower()
        is_hidden = G.nodes[node].get('hidden', False)
        
        # Assign colours and sizes based on device type and whether it's hidden
        if is_hidden:
            # Hidden devices have distinct appearance
            node_colors.append('crimson')
            node_sizes.append(900)
            node_borders.append('darkred')
            border_widths.append(2)
        elif 'edge' in device_type or ('gateway' in device_type and simulation_type == "edge_hidden_network"):
            # Edge gateways have special styling
            node_colors.append('purple')
            node_sizes.append(1200)
            node_borders.append('darkviolet')
            border_widths.append(3)
        elif any(term in device_type for term in ['plc', 'controller']):
            node_colors.append('orangered')
            node_sizes.append(1000)
            node_borders.append('darkred')
            border_widths.append(2)
        elif any(term in device_type for term in ['router', 'gateway', 'firewall']) and not 'edge' in device_type:
            node_colors.append('royalblue')
            node_sizes.append(1200)
            node_borders.append('darkblue')
            border_widths.append(2)
        elif any(term in device_type for term in ['scada', 'hmi', 'workstation']):
            node_colors.append('mediumseagreen')
            node_sizes.append(1100)
            node_borders.append('darkgreen')
            border_widths.append(2)
        elif any(term in device_type for term in ['sensor', 'field']):
            node_colors.append('gold')
            node_sizes.append(800)
            node_borders.append('goldenrod')
            border_widths.append(2)
        elif 'silent' in device_type:
            # Silent devices have distinct appearance
            node_colors.append('gray')
            node_sizes.append(900)
            node_borders.append('darkslategray')
            border_widths.append(2)
        else:
            node_colors.append('lightgray')
            node_sizes.append(900)
            node_borders.append('gray')
            border_widths.append(1.5)
    
    return node_colors, node_sizes, node_borders, border_widths

def _create_visualisation(G: nx.DiGraph, pos: Dict[str, Tuple[float, float]],
                        node_colors: List, node_sizes: List, 
                        node_borders: List, border_widths: List,
                        network_zones: Dict[str, float],
                        save_path: str, simulation_type: Optional[str]) -> None:
    """Create and save the network topology visualisation."""
    # Create a larger figure for better spacing
    plt.figure(figsize=(20, 16))
    
    # Draw the network with clearer edges
    nx.draw_networkx_edges(G, pos, 
                        width=2.0, 
                        alpha=0.6, 
                        arrowsize=20, 
                        edge_color='darkslategray',
                        connectionstyle='arc3,rad=0.1')  # Curved edges
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, 
                        node_color=node_colors, 
                        node_size=node_sizes, 
                        alpha=0.85,
                        linewidths=border_widths,
                        edgecolors=node_borders)
    
    # Create separate, non-overlapping labels
    for node, (x, y) in pos.items():
        device_type = G.nodes[node]['type']
        
        # Create a more compact label
        label = f"{node}\n({device_type})"
        
        # Adjust label position below the node with background
        plt.annotate(
            label,
            xy=(x, y), 
            xytext=(0, -40),  # Place labels further below nodes
            textcoords="offset points",
            bbox=dict(boxstyle="round,pad=0.4", 
                    fc="white", 
                    ec="gray", 
                    alpha=0.9,
                    linewidth=1),
            ha='center', 
            va='top', 
            fontsize=12,
            fontweight='bold'
        )
    
    # Add network zone labels on the left side with better styling
    for network, y_pos in network_zones.items():
        if network in [net for net, devices in G.nodes(data='network') if net == network]:
            plt.text(
                -0.05, y_pos, 
                f"{network} NETWORK", 
                fontsize=16, 
                fontweight='bold',
                ha='right', 
                va='center',
                bbox=dict(boxstyle="round,pad=0.6", 
                        fc="lightgray", 
                        ec="black", 
                        alpha=0.8,
                        linewidth=2)
            )
    
    if simulation_type == "edge_hidden_network":
        title = "Edge/Hidden Network Topology"
    else:
        title = "Standard Network Topology"
        
    plt.title(title, fontsize=22, fontweight='bold', pad=30)
    plt.axis('off')
    
    handles = []
    labels = []
    
    # Customise legend based on simulation type
    if simulation_type == "edge_hidden_network":
        device_types = {
            'Edge Gateway': 'purple',
            'Router/Gateway': 'royalblue',
            'PLC/Controller': 'orangered',
            'SCADA/HMI': 'mediumseagreen',
            'Field Device/Sensor': 'gold',
            'Hidden Device': 'crimson',
            'Silent Device': 'gray',
            'Other Device': 'lightgray'
        }
    else:
        device_types = {
            'Router/Gateway': 'royalblue',
            'PLC/Controller': 'orangered',
            'SCADA/HMI': 'mediumseagreen',
            'Field Device/Sensor': 'gold',
            'Other Device': 'lightgray'
        }
    
    for label, color in device_types.items():
        handles.append(plt.Line2D([0], [0], 
                                marker='o', 
                                markersize=15, 
                                markerfacecolor=color,
                                markeredgecolor='black',
                                markeredgewidth=1,
                                color='w'))
        labels.append(label)
    
    plt.legend(handles=handles, 
            labels=labels, 
            loc='upper right', 
            fontsize=14,
            framealpha=0.9,
            edgecolor='black')
    
    plt.tight_layout()
    plt.subplots_adjust(left=0.15, right=0.85, top=0.9, bottom=0.1)
    
    node_count = G.number_of_nodes()
    edge_count = G.number_of_edges()
    stats_text = f"Nodes: {node_count}\nEdges: {edge_count}"
    plt.figtext(0.95, 0.05, stats_text, ha='right', fontsize=12, 
              bbox=dict(boxstyle="round,pad=0.4", fc="white", ec="gray", alpha=0.9))
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()