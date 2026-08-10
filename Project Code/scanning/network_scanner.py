#!/usr/bin/env python3
"""
Network Scanner for Industrial Control Systems

Provides PCAP-based analysis and topology visualisation capabilities
for industrial control system networks.
"""

import os
import json
import re
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple, Set
import matplotlib.pyplot as plt
import numpy as np

class NetworkScanner:
    """
    Network scanner that analyses PCAP files to discover network topology
    and communications in industrial control system environments.
    """

    def __init__(self, output_dir: Optional[str] = None, 
                simulation_type: Optional[str] = None):
        """Initialise network scanner with configurable parameters."""
        self.logger = self._setup_logging()
        
        # Core data structures
        self.comprehensive_results = {}
        self.known_protocols = {
            502: "Modbus TCP",
            20000: "DNP3",
            47808: "BACnet",
            8099: "Proprietary/Custom",
            22: "SSH/Maintenance",
            9000: "Edge Gateway",
            2323: "Firmware Update"
        }
        
        # Configuration
        self.results_dir = self._setup_results_directory(output_dir)
        self.simulation_type = simulation_type or "generic"
        
    def _setup_results_directory(self, output_dir: Optional[str]) -> str:
        """Set up and validate results directory for scanner output."""
        # Check environment variable first
        env_results_dir = os.environ.get("SCAN_RESULTS_DIR")
        if env_results_dir:
            return self._validate_directory(env_results_dir)
        
        # Use provided output directory
        if output_dir:
            return self._validate_directory(output_dir)
        
        # Create default timestamped directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_dir = f"scan_results_{timestamp}"
        return self._validate_directory(default_dir)
    
    def _validate_directory(self, directory: str) -> str:
        """Validate and create results directory if needed."""
        try:
            os.makedirs(directory, exist_ok=True)
            if not os.access(directory, os.W_OK):
                raise PermissionError("Directory is not writable")
            return directory
        except (OSError, PermissionError) as e:
            self.logger.error(f"Error with directory {directory}: {e}. Falling back to current directory.")
            return "."

    def _setup_logging(self) -> logging.Logger:
        """Configure logging for network scanner."""
        logger = logging.getLogger("NetworkScanner")
        logger.propagate = False
        
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            
            logger.addHandler(console_handler)
        
        return logger

    def parse_simulation_output(self, output_file: str) -> bool:
        """
        Parse simulation output to extract network information and analyse PCAP files.
        
        Args:
            output_file: Path to simulation output file
            
        Returns:
            True if parsing was successful, False otherwise
        """
        try:
            with open(output_file, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            self.logger.error(f"Output file not found: {output_file}")
            return False
        
        try:
            # Extract device and network information
            self._extract_network_information(content)
            
            # Extract communication patterns
            self._extract_communication_patterns(content)
            
            # Initialize the comprehensive results structure
            self._initialize_comprehensive_results()
            
            # Analyze PCAP files to discover connections and hidden devices
            pcap_connections, hidden_devices = self.analyze_pcaps_for_enhanced_topology()
            
            # Process communication pairs from simulation
            self._process_communication_pairs()
            
            # Generate consolidated results file
            self._generate_consolidated_results()
            
            # Create visualizations
            self._create_visualisations()
            
            self.logger.info(f"Network analysis completed successfully")
            return True
        
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return False

    def _extract_network_information(self, content: str) -> None:
        """Extract network device information from simulation output."""
        self.devices = {}
        
        try:
            devices_found = 0
            hidden_devices = 0
            
            if "Network Addresses:" in content:
                network_section = content.split("Network Addresses:")[1]
                if "DEVICE SUMMARY" in network_section:
                    network_section = network_section.split("DEVICE SUMMARY")[0]
                
                ip_pattern = r'([A-Za-z0-9\s\(\)]+):\s*(?:(\d+\.\d+\.\d+\.\d+)|([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}:[0-9A-Fa-f:]+))'
                matches = re.findall(ip_pattern, network_section)
                
                for match in matches:
                    try:
                        device_type = match[0].strip()
                        original_ip = match[1] or match[2]
                        
                        if not original_ip:
                            continue
                        
                        # Convert to IPv4 if needed
                        ipv4 = original_ip
                        if '-' in original_ip and ':' in original_ip:
                            ipv4 = self._mac_style_to_ipv4(original_ip)
                            if not ipv4:
                                continue
                        
                        # Determine network
                        networks = [
                            "IT NETWORK", "DMZ NETWORK", "CONTROL NETWORK", 
                            "OT CONTROL NETWORK", "PROCESS NETWORK", 
                            "OT PROCESS NETWORK", "MAINTENANCE NETWORK"
                        ]
                        current_network = next(
                            (net for net in networks 
                            if net in network_section.split(device_type)[0].split("\n\n")[-1]), 
                            "CONTROL NETWORK"
                        )
                        
                        is_hidden = any(h in device_type.lower() for h in ['hidden', 'silent', 'legacy', 'backup'])
                        
                        # Create device object representation
                        device = {
                            'device_type': device_type,
                            'network': current_network,
                            'hidden': is_hidden,
                            'original_ip': original_ip
                        }
                        
                        # Store device
                        self.devices[ipv4] = device
                        
                        devices_found += 1
                        if is_hidden:
                            hidden_devices += 1
                    
                    except Exception:
                        continue
            
            self.logger.info(f"Total Devices Found: {devices_found}")
            self.logger.info(f"Hidden Devices: {hidden_devices}")
        
        except Exception as e:
            self.logger.error(f"Network information extraction failed: {e}")

    def _extract_communication_patterns(self, content: str) -> None:
        """Extract communication patterns from simulation output."""
        self.communications = []
        self.communication_pairs = {}
        
        # Extract device information from the DEVICE SUMMARY section
        device_summary = {}
        device_ref_to_ip = {}
        
        device_summary_section = re.search(r'DEVICE SUMMARY:(.*?)(?:Starting simulation|\Z)', content, re.DOTALL)
        if device_summary_section:
            summary_text = device_summary_section.group(1)
            
            # Parse client-server connections from device summary
            device_pattern = r'Device\s+([^:]+):\s*(?:Servers:[^C]*)?(?:Clients:(.*?))?(?:\n\n|\Z)'
            for match in re.finditer(device_pattern, summary_text, re.DOTALL):
                device_ref = match.group(1).strip()
                clients_section = match.group(2)
                
                if clients_section:
                    client_connections = re.findall(r'- ([a-zA-Z0-9_]+) -> ([0-9A-Za-z\-:.]+):(\d+)', clients_section)
                    if client_connections:
                        device_summary[device_ref] = client_connections
            
            # Parse IP to device mapping from Network Addresses section
            network_section = re.search(r'Network Addresses:(.*?)(?:DEVICE SUMMARY|\Z)', content, re.DOTALL)
            if network_section:
                network_text = network_section.group(1)
                
                # Find all device names and MAC/IP addresses
                device_mappings = re.findall(r'([^:]+):\s*([0-9A-Fa-f\-:.]+)', network_text)
                
                # Map device refs to IPs
                for device_name, mac_or_ip in device_mappings:
                    device_name = device_name.strip()
                    
                    # If it's already an IPv4 address
                    if re.match(r'\d+\.\d+\.\d+\.\d+', mac_or_ip):
                        # Find corresponding device
                        for ref in device_summary.keys():
                            if ref in device_name or device_name in ref:
                                device_ref_to_ip[ref] = mac_or_ip
                                break
        
        # Extract communications from "At time" log entries
        comm_pattern = r"At time \+([0-9.]+)s (client|server) (sent|received) (\d+) bytes (from|to) ([0-9.]+) port (\d+)"
        
        for line in content.split('\n'):
            matches = re.findall(comm_pattern, line)
            
            for match in matches:
                try:
                    time, entity, action, size, direction, ip, port = match
                    
                    # Store the communication
                    comm_entry = {
                        "time": float(time),
                        "entity": entity.lower(),
                        "action": action.lower(),
                        "size": int(size),
                        "direction": direction.lower(),
                        "ip": ip,
                        "port": int(port) if port.isdigit() else 0,
                        "protocol": self.known_protocols.get(int(port) if port.isdigit() else 0, f"Unknown (Port {port})")
                    }
                    
                    self.communications.append(comm_entry)
                except Exception:
                    continue
        
        # Use device summary to establish connections
        for device_ref, connections in device_summary.items():
            if device_ref in device_ref_to_ip:
                source_ip = device_ref_to_ip[device_ref]
                
                if source_ip not in self.communication_pairs:
                    self.communication_pairs[source_ip] = []
                
                for client_name, target_addr, port in connections:
                    # If target is an IPv4 address
                    if re.match(r'\d+\.\d+\.\d+\.\d+', target_addr):
                        target_ip = target_addr
                        if target_ip not in self.communication_pairs[source_ip]:
                            self.communication_pairs[source_ip].append(target_ip)
        
        self.logger.info(f"Total Communications Extracted: {len(self.communications)}")
        self.logger.info(f"Total connection pairs found: {len(self.communication_pairs)}")

    def _mac_style_to_ipv4(self, mac_style: str) -> Optional[str]:
        """Convert MAC-style address to IPv4 format."""
        try:
            if mac_style.startswith("03-04-"):
                hex_part = mac_style[6:]
                hex_octets = hex_part.split(":")
                if len(hex_octets) == 4:
                    dec_octets = [int(octet, 16) for octet in hex_octets]
                    return ".".join(str(octet) for octet in dec_octets)
            return None
        except Exception:
            return None

    def _initialize_comprehensive_results(self):
        """Initialize the comprehensive results structure."""
        self.comprehensive_results = {}
        
        # Add all known devices to the results
        for ip, device in self.devices.items():
            self.comprehensive_results[ip] = {
                "device_info": {
                    "type": device.get('device_type', 'Unknown'),
                    "network": device.get('network', 'Unknown'),
                    "hidden": device.get('hidden', False)
                },
                "connections": [],
                "detection_info": {}
            }

    def _process_communication_pairs(self):
        """Process communication pairs from simulation and add to comprehensive results."""
        for src_ip, target_ips in self.communication_pairs.items():
            if src_ip not in self.comprehensive_results:
                # If source IP not in results, create entry
                if src_ip in self.devices:
                    self.comprehensive_results[src_ip] = {
                        "device_info": {
                            "type": self.devices[src_ip].get('device_type', 'Unknown'),
                            "network": self.devices[src_ip].get('network', 'Unknown'),
                            "hidden": self.devices[src_ip].get('hidden', False)
                        },
                        "connections": [],
                        "detection_info": {}
                    }
                else:
                    self.comprehensive_results[src_ip] = {
                        "device_info": {
                            "type": "Unknown",
                            "network": "Unknown",
                            "hidden": False
                        },
                        "connections": [],
                        "detection_info": {}
                    }
            
            # Add each connection
            for target_ip in target_ips:
                self.comprehensive_results[src_ip]["connections"].append({
                    "target": target_ip,
                    "confidence": 1.0,  # Full confidence for simulation data
                    "protocol": self._determine_protocol_for_connection(src_ip, target_ip)
                })
                
                # Make sure target is in results
                if target_ip not in self.comprehensive_results:
                    if target_ip in self.devices:
                        self.comprehensive_results[target_ip] = {
                            "device_info": {
                                "type": self.devices[target_ip].get('device_type', 'Unknown'),
                                "network": self.devices[target_ip].get('network', 'Unknown'),
                                "hidden": self.devices[target_ip].get('hidden', False)
                            },
                            "connections": [],
                            "detection_info": {}
                        }
                    else:
                        self.comprehensive_results[target_ip] = {
                            "device_info": {
                                "type": "Unknown",
                                "network": "Unknown",
                                "hidden": False
                            },
                            "connections": [],
                            "detection_info": {}
                        }
    def create_protocol_heatmap(self) -> str:
        """
        Create a heatmap showing protocol usage across network zones.
        
        Returns:
            Path to the generated visualisation
        """
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            import seaborn as sns
            
            # Extract network zones and protocols
            network_zones = set()
            protocols = set()
            
            # First pass to collect all networks and protocols
            for device_info in self.comprehensive_results.values():
                network = device_info.get("device_info", {}).get("network", "Unknown")
                network_zones.add(network)
                
                for conn in device_info.get("connections", []):
                    if isinstance(conn, dict) and "protocol" in conn:
                        protocols.add(conn["protocol"])
            
            # Handle empty data
            if not network_zones or not protocols:
                return ""
                
            # Convert to sorted lists
            network_zones = sorted(list(network_zones))
            protocols = sorted(list(protocols))
            
            # Initialize matrix
            heatmap_data = np.zeros((len(network_zones), len(protocols)))
            
            # Second pass to count protocols by network
            for device_info in self.comprehensive_results.values():
                network = device_info.get("device_info", {}).get("network", "Unknown")
                if network not in network_zones:  # Skip if network not recognized
                    continue
                    
                net_idx = network_zones.index(network)
                
                for conn in device_info.get("connections", []):
                    if isinstance(conn, dict) and "protocol" in conn:
                        protocol = conn["protocol"]
                        if protocol in protocols:  # Skip if protocol not recognized
                            proto_idx = protocols.index(protocol)
                            heatmap_data[net_idx, proto_idx] += 1
            
            # Create plot
            plt.figure(figsize=(12, 8))
            
            # Generate heatmap
            ax = sns.heatmap(heatmap_data, annot=True, fmt="g", 
                        xticklabels=protocols, yticklabels=network_zones, 
                        cmap="YlGnBu", linewidths=.5)
            
            # Add labels
            plt.title(f"Protocol Distribution by Network Zone - {self.simulation_type}", fontsize=16)
            plt.xlabel("Protocol", fontsize=12)
            plt.ylabel("Network Zone", fontsize=12)
            
            # Rotate x-axis labels for better readability
            plt.xticks(rotation=45, ha="right")
            
            # Save the visualisation
            save_path = os.path.join(self.results_dir, f"{self.simulation_type}_protocol_heatmap.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return save_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate protocol heatmap: {e}")
            return ""

    def create_detection_confidence_chart(self) -> str:
        """
        Create a chart showing detection confidence for hidden devices.
        
        Returns:
            Path to the generated visualisation
        """
        try:
            import matplotlib.pyplot as plt
            
            # Extract devices with detection info
            detected_devices = []
            
            for ip, device_info in self.comprehensive_results.items():
                if "pcap_hidden_device" in device_info.get("detection_info", {}):
                    detected_info = device_info["detection_info"]["pcap_hidden_device"]
                    device_type = device_info.get("device_info", {}).get("type", "Unknown Device")
                    is_known = device_info.get("device_info", {}).get("hidden", False)
                    
                    detected_devices.append({
                        "ip": ip,
                        "type": device_type,
                        "confidence": detected_info.get("confidence", 0.0),
                        "known_hidden": is_known,
                        "evidence_count": len(detected_info.get("evidence", []))
                    })
            
            # Handle empty data
            if not detected_devices:
                return ""
                
            # Sort by confidence
            detected_devices.sort(key=lambda x: x["confidence"], reverse=True)
            
            # Create plot
            fig, ax = plt.subplots(figsize=(12, 7))
            
            # Extract data for plotting
            ips = [d["ip"] for d in detected_devices]
            confidences = [d["confidence"] for d in detected_devices]
            colors = ['orangered' if d["known_hidden"] else 'purple' for d in detected_devices]
            
            # Create bars
            bars = ax.bar(ips, confidences, color=colors, alpha=0.8)
            
            # Add evidence count as text on bars
            for i, bar in enumerate(bars):
                height = bar.get_height()
                count = detected_devices[i]["evidence_count"]
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                        f"{count} evidence",
                        ha='center', va='bottom', 
                        fontsize=9, rotation=0)
            
            # Add device type as labels
            device_labels = [f"{ips[i]}\n({detected_devices[i]['type']})" for i in range(len(ips))]
            ax.set_xticks(range(len(ips)))
            ax.set_xticklabels(device_labels, rotation=45, ha='right')
            
            # Add labels and title
            ax.set_ylabel('Detection Confidence', fontsize=12)
            ax.set_title(f'Hidden Device Detection Confidence - {self.simulation_type}', fontsize=16)
            
            # Add a horizontal line at confidence threshold
            ax.axhline(y=0.4, color='gray', linestyle='--', alpha=0.7)
            ax.text(len(ips) - 1, 0.41, 'Detection Threshold', ha='right', va='bottom', 
                    color='gray', fontsize=10)
            
            # Add legend
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='orangered', edgecolor='black', label='Known Hidden'),
                Patch(facecolor='purple', edgecolor='black', label='Detected Hidden')
            ]
            ax.legend(handles=legend_elements, loc='upper right')
            
            # Set y-axis limits
            ax.set_ylim(0, 1.1)  # 0 to 1 with a little margin
            
            # Show confidence value on bars
            for i, v in enumerate(confidences):
                ax.text(i, v + 0.05, f"{v:.2f}", ha='center', fontsize=9)
            
            plt.tight_layout()
            
            # Save the visualisation
            save_path = os.path.join(self.results_dir, f"{self.simulation_type}_detection_confidence.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return save_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate detection confidence chart: {e}")
            return ""
    
    def _create_protocol_distribution(self) -> None:
        """Create pie chart showing distribution of protocols."""
        protocol_counts = defaultdict(int)
        
        # Count protocols from comprehensive results connections
        for device_info in self.comprehensive_results.values():
            for conn in device_info.get("connections", []):
                if isinstance(conn, dict) and "protocol" in conn:
                    protocol = conn.get("protocol", "Unknown")
                    protocol_counts[protocol] += 1
        
        # Create a pie chart
        plt.figure(figsize=(10, 8))
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        
        # Only create pie chart if we have data
        if counts:
            plt.pie(counts, labels=protocols, autopct='%1.1f%%')
            plt.title('Protocol Distribution in Network')
            plt.axis('equal')
            
            try:
                viz_path = os.path.join(self.results_dir, f"{self.simulation_type}_protocol_distribution.png")
                plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                plt.close()
                self.logger.info(f"Created protocol distribution chart: {viz_path}")
            except Exception as e:
                self.logger.error(f"Failed to save protocol distribution chart: {e}")
                plt.close()
        else:
            plt.close()
    

    def create_hidden_device_visualization(self) -> str:
        """
        Create a specialised visualisation highlighting hidden devices and connections.
        
        Returns:
            Path to the generated visualisation
        """
        try:
            import matplotlib.pyplot as plt
            import networkx as nx
            
            # Create directed graph
            G = nx.DiGraph()
            
            # Track hidden nodes for visual distinction
            hidden_nodes = set()
            detected_nodes = set()
            
            # Extract nodes from devices
            for ip, device_info in self.comprehensive_results.items():
                # Get device information
                device_type = device_info.get("device_info", {}).get("type", "Unknown")
                is_known_hidden = device_info.get("device_info", {}).get("hidden", False)
                has_detection = "pcap_hidden_device" in device_info.get("detection_info", {})
                
                # Add node with attributes
                G.add_node(ip, type=device_type, hidden=is_known_hidden, detected=has_detection)
                
                # Track hidden and detected nodes
                if is_known_hidden:
                    hidden_nodes.add(ip)
                if has_detection:
                    detected_nodes.add(ip)
            
            # Add edges based on connections
            for ip, device_info in self.comprehensive_results.items():
                for connection in device_info.get("connections", []):
                    if isinstance(connection, dict) and "target" in connection:
                        target = connection["target"]
                        protocol = connection.get("protocol", "Unknown")
                        confidence = connection.get("confidence", 0.0)
                        
                        # Only add if both nodes exist
                        if target in G.nodes and ip in G.nodes:
                            G.add_edge(ip, target, protocol=protocol, confidence=confidence)
            
            # Create plot
            plt.figure(figsize=(14, 10))
            
            # Generate layout focused on hidden devices
            center_nodes = hidden_nodes.union(detected_nodes)
            if center_nodes:
                pos = nx.spring_layout(G, k=0.3)
            else:
                pos = nx.spring_layout(G, k=0.3)
            
            # Draw normal nodes
            normal_nodes = [n for n in G.nodes if n not in hidden_nodes and n not in detected_nodes]
            if normal_nodes:
                nx.draw_networkx_nodes(G, pos, nodelist=normal_nodes, 
                                    node_color='lightblue', alpha=0.7, node_size=800)
            
            # Draw known hidden nodes
            if hidden_nodes:
                nx.draw_networkx_nodes(G, pos, nodelist=hidden_nodes,
                                    node_color='orangered', alpha=0.9, node_size=1000)
            
            # Draw detected (but not known) hidden nodes
            detected_only = detected_nodes - hidden_nodes
            if detected_only:
                nx.draw_networkx_nodes(G, pos, nodelist=detected_only,
                                    node_color='purple', alpha=0.9, node_size=900)
            
            # Draw edges with varying thickness based on confidence
            for u, v, data in G.edges(data=True):
                # Skip if either node doesn't have a position
                if u not in pos or v not in pos:
                    continue
                    
                confidence = data.get('confidence', 0.5)
                width = 1 + 3 * confidence  # Scale width based on confidence
                
                # Color edges connected to hidden nodes differently
                if u in hidden_nodes or v in hidden_nodes or u in detected_nodes or v in detected_nodes:
                    color = 'red'
                    alpha = 0.8
                else:
                    color = 'gray'
                    alpha = 0.5
                    
                # Draw a single edge
                nx.draw_networkx_edges(G, pos, edgelist=[(u, v)], 
                                    width=width, alpha=alpha, edge_color=color,
                                    connectionstyle='arc3,rad=0.15')
            
            # Add labels with IP and type
            labels = {}
            for node in G.nodes():
                node_type = G.nodes[node].get('type', 'Unknown')
                # Create a shorter label
                labels[node] = f"{node}\n({node_type})"
            
            nx.draw_networkx_labels(G, pos, labels=labels, font_size=9, font_weight='bold')
            
            # Add legend
            from matplotlib.lines import Line2D
            legend_elements = [
                Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', 
                    markersize=15, label='Normal Device'),
                Line2D([0], [0], marker='o', color='w', markerfacecolor='orangered', 
                    markersize=15, label='Known Hidden Device'),
                Line2D([0], [0], marker='o', color='w', markerfacecolor='purple', 
                    markersize=15, label='Detected Hidden Device'),
                Line2D([0], [0], color='gray', lw=2, label='Normal Connection'),
                Line2D([0], [0], color='red', lw=2, label='Hidden Connection')
            ]
            plt.legend(handles=legend_elements, loc='upper right')
            
            # Add title
            plt.title(f"Hidden Device Detection - {self.simulation_type}", fontsize=16)
            
            # Save the visualisation
            save_path = os.path.join(self.results_dir, f"{self.simulation_type}_hidden_device_analysis.png")
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return save_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate hidden device visualization: {e}")
            return ""

    def _clean_decimal_values(self, obj):
        """Recursively convert decimal values to float for JSON serialization."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                obj[key] = self._clean_decimal_values(value)
        elif isinstance(obj, list):
            return [self._clean_decimal_values(item) for item in obj]
        elif hasattr(obj, '__float__') and not isinstance(obj, (int, float)):
            return float(obj)
        elif isinstance(obj, set):
            return list(obj)
        return obj

    def _generate_consolidated_results(self) -> None:
        """Generate consolidated results file with network topology and analysis."""
        # Add scanning metadata
        metadata = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "simulation_type": self.simulation_type,
            "total_devices": len(self.devices),
            "total_hidden_devices": sum(1 for d in self.devices.values() if d.get('hidden', False)),
            "visualizations": {
                "topology": f"{self.simulation_type}_topology.png",
                "protocol_distribution": f"{self.simulation_type}_protocol_distribution.png"
            }
        }
        
        # Add statistical summaries
        network_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for device in self.devices.values():
            network_counts[device.get('network', 'Unknown')] += 1
            type_counts[device.get('device_type', 'Unknown')] += 1
        
        statistics = {
            "network_distribution": dict(network_counts),
            "device_type_distribution": dict(type_counts)
        }
        
        # Add to comprehensive results
        comprehensive_package = {
            "metadata": metadata,
            "statistics": statistics,
            "devices": self.comprehensive_results
        }
        
        # Clean any non-serializable values
        self._clean_decimal_values(comprehensive_package)
        
        # Save to file
        try:
            output_path = os.path.join(self.results_dir, f"{self.simulation_type}_comprehensive_results.json")
            with open(output_path, 'w') as f:
                json.dump(comprehensive_package, f, indent=2)
            
            self.logger.info(f"Saved comprehensive results to: {output_path}")
            
            # Also save a simplified summary for quick reference
            summary = {
                "simulation_type": self.simulation_type,
                "total_devices": len(self.devices),
                "hidden_devices": sum(1 for d in self.devices.values() if d.get('hidden', False)),
                "network_distribution": statistics["network_distribution"],
                "device_type_distribution": statistics["device_type_distribution"]
            }
            
            summary_path = os.path.join(self.results_dir, f"{self.simulation_type}_summary.json")
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
        
        except Exception as e:
            self.logger.error(f"Failed to save comprehensive results: {e}")

    def _create_visualisations(self) -> None:
        """Generate visualisations from analysis data."""
        self._create_topology()
        self._create_protocol_distribution()
        self.create_hidden_device_visualization()
        self.create_protocol_heatmap()
        self.create_detection_confidence_chart()

    def _create_topology(self) -> str:
        """Create single topology visualisation based on comprehensive results."""
        try:
            # Import required functions here to avoid circular imports
            from utils.topology import generate_network_topology
            
            # Get devices from comprehensive results
            topology_devices = []
            for ip, info in self.comprehensive_results.items():
                device_info = info.get("device_info", {})
                device_dict = {
                    'ip': ip,
                    'type': device_info.get("type", "Unknown"),
                    'network': device_info.get("network", "Unknown"),
                    'hidden': device_info.get("hidden", False)
                }
                
                # Add PCAP-specific information if available
                if "detection_info" in info and "pcap_hidden_device" in info["detection_info"]:
                    pcap_info = info["detection_info"]["pcap_hidden_device"]
                    device_dict["pcap_confidence"] = pcap_info.get("confidence", 0)
                    device_dict["pcap_protocols"] = list(pcap_info.get("protocols", []))
                
                topology_devices.append(device_dict)
            
            # Extract connections in simple list format
            connections = {}
            
            for src_ip, info in self.comprehensive_results.items():
                if info.get("connections"):
                    connections[src_ip] = []
                    # Process each connection to extract just the target IP
                    for conn in info["connections"]:
                        if isinstance(conn, dict) and "target" in conn:
                            target_ip = conn["target"]
                            # Avoid duplicates by checking if already added
                            if target_ip not in connections[src_ip]:
                                connections[src_ip].append(target_ip)
            
            # Generate topology with shorter name
            save_path = os.path.join(self.results_dir, f"{self.simulation_type}_topology.png")
            
            # Generate the visualisation
            generate_network_topology(
                devices=topology_devices,
                connections=connections,
                save_path=save_path,
                simulation_type=self.simulation_type
            )
            
            self.logger.info(f"Generated network topology: {save_path}")
            return save_path
        except Exception as e:
            self.logger.error(f"Failed to generate network topology: {e}")
            return ""

    def _analyze_packet_for_hidden_activity(self, src_ip, dst_ip, protocol, packet, hidden_device_candidates):
        """
        Analyse packet for signs of hidden device activity.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: Protocol used in the packet
            packet: Scapy packet object
            hidden_device_candidates: Dictionary to store hidden device candidates
        """
        # Check if any of the IPs are unknown (not in our device list)
        for ip in [src_ip, dst_ip]:
            if ip not in self.devices:
                if ip not in hidden_device_candidates:
                    hidden_device_candidates[ip] = {
                        'ip': ip,
                        'confidence': 0.1,  # Initial confidence
                        'evidence': [],
                        'protocols': set(),
                        'connections': set()
                    }
                    
                    # Add evidence only once
                    evidence_text = f"Unknown IP in network traffic"
                    if evidence_text not in hidden_device_candidates[ip]['evidence']:
                        hidden_device_candidates[ip]['evidence'].append(evidence_text)
                        hidden_device_candidates[ip]['confidence'] += 0.1
        
        # Check for communication with known hidden devices
        for ip in [src_ip, dst_ip]:
            if ip in self.devices and self.devices[ip].get('hidden', False):
                other_ip = dst_ip if ip == src_ip else src_ip
                
                if other_ip not in hidden_device_candidates:
                    hidden_device_candidates[other_ip] = {
                        'ip': other_ip,
                        'confidence': 0.1,
                        'evidence': [],
                        'protocols': set(),
                        'connections': set()
                    }
                
                # Add evidence only once
                evidence_text = f"Communication with known hidden device {ip}"
                if evidence_text not in hidden_device_candidates[other_ip]['evidence']:
                    hidden_device_candidates[other_ip]['evidence'].append(evidence_text)
                    hidden_device_candidates[other_ip]['confidence'] += 0.3
        
        # Check for unusual protocols
        if protocol in ["Proprietary/Custom", "Unknown"]:
            for ip in [src_ip, dst_ip]:
                if ip not in hidden_device_candidates:
                    hidden_device_candidates[ip] = {
                        'ip': ip,
                        'confidence': 0.1,
                        'evidence': [],
                        'protocols': set(),
                        'connections': set()
                    }
                
                # Add evidence only once
                evidence_text = f"Uses unusual protocol: {protocol}"
                if evidence_text not in hidden_device_candidates[ip]['evidence']:
                    hidden_device_candidates[ip]['evidence'].append(evidence_text)
                    hidden_device_candidates[ip]['confidence'] += 0.2
                    hidden_device_candidates[ip]['protocols'].add(protocol)
        
        # Track connections (bidirectionally)
        for source, target in [(src_ip, dst_ip), (dst_ip, src_ip)]:
            if source in hidden_device_candidates:
                hidden_device_candidates[source]['connections'].add(target)

    def analyze_traffic_patterns(self, traffic_patterns, hidden_device_candidates):
        """
        Analyse traffic patterns with enhanced ICS-specific detection.
        
        Args:
            traffic_patterns: Dictionary mapping IPs to their traffic patterns
            hidden_device_candidates: Dictionary to store hidden device candidates
        """
        # Define patterns common in industrial networks
        ics_patterns = {
            "polling": {
                "interval_cv_threshold": 0.2,  # Coefficient of variation threshold
                "min_packets": 3,
                "min_period": 0.5,  # seconds
                "max_period": 60.0   # seconds
            },
            "heartbeat": {
                "interval_cv_threshold": 0.05,  # Very regular
                "min_packets": 4,
                "size_variation_threshold": 0.1  # Consistent size
            }
        }
        
        # Analyse each IP's traffic
        for ip, patterns in traffic_patterns.items():
            if len(patterns) < 3:
                continue
            
            # Sort by timestamp
            patterns.sort(key=lambda x: x['timestamp'])
            
            # Calculate time differences between consecutive packets
            time_diffs = []
            for i in range(1, len(patterns)):
                time_diffs.append(patterns[i]['timestamp'] - patterns[i-1]['timestamp'])
            
            if not time_diffs:
                continue
            
            # Calculate basic statistics
            mean_diff = sum(time_diffs) / len(time_diffs)
            std_dev = (sum((d - mean_diff)**2 for d in time_diffs) / len(time_diffs))**0.5
            
            # Calculate coefficient of variation (CV) for timing regularity
            if mean_diff > 0:
                timing_cv = std_dev / mean_diff
                
                # Analyse packet sizes
                packet_sizes = [p['size'] for p in patterns]
                mean_size = sum(packet_sizes) / len(packet_sizes)
                size_std_dev = (sum((s - mean_size)**2 for s in packet_sizes) / len(packet_sizes))**0.5
                
                size_cv = size_std_dev / mean_size if mean_size > 0 else float('inf')
                
                # Detect patterns
                detected_pattern = None
                confidence = 0.0
                evidence = []
                
                # Check for polling pattern (regular intervals, client-initiated)
                if (timing_cv <= ics_patterns["polling"]["interval_cv_threshold"] and 
                    len(patterns) >= ics_patterns["polling"]["min_packets"] and
                    ics_patterns["polling"]["min_period"] <= mean_diff <= ics_patterns["polling"]["max_period"]):
                    
                    detected_pattern = "polling"
                    base_confidence = 0.6
                    
                    # Adjust confidence based on how regular the timing is
                    regularity_factor = 1.0 - (timing_cv / ics_patterns["polling"]["interval_cv_threshold"])
                    confidence = min(0.9, base_confidence + (regularity_factor * 0.3))
                    
                    evidence.append(f"Regular polling pattern detected (CV={timing_cv:.3f}, period={mean_diff:.2f}s)")
                    
                    # Check for control system behaviours
                    if any('protocol' in p and p.get('protocol') in ['Modbus TCP', 'DNP3', 'BACnet'] for p in patterns):
                        evidence.append(f"Using industrial protocol for polling")
                        confidence += 0.1
                
                # Check for heartbeat pattern (very regular, small packets)
                elif (timing_cv <= ics_patterns["heartbeat"]["interval_cv_threshold"] and 
                    len(patterns) >= ics_patterns["heartbeat"]["min_packets"] and
                    size_cv <= ics_patterns["heartbeat"]["size_variation_threshold"]):
                    
                    detected_pattern = "heartbeat"
                    confidence = 0.7
                    evidence.append(f"Heartbeat pattern detected (CV={timing_cv:.3f}, size CV={size_cv:.3f})")
                
                # Check for potential silent/hidden devices
                if detected_pattern:
                    # Initialize entry if it doesn't exist
                    if ip not in hidden_device_candidates:
                        hidden_device_candidates[ip] = {
                            'ip': ip,
                            'confidence': 0.1,
                            'evidence': [],
                            'protocols': set(),
                            'connections': set(),
                            'pattern': detected_pattern
                        }
                    
                    # Update candidate details
                    for evidence_item in evidence:
                        if evidence_item not in hidden_device_candidates[ip]['evidence']:
                            hidden_device_candidates[ip]['evidence'].append(evidence_item)
                    
                    # Update confidence if our new detection is higher
                    hidden_device_candidates[ip]['confidence'] = max(
                        hidden_device_candidates[ip]['confidence'],
                        confidence
                    )
                    
                    # Add protocol information
                    for p in patterns:
                        if 'protocol' in p:
                            hidden_device_candidates[ip]['protocols'].add(p['protocol'])
                
                # Ensure the 'connections' set exists before trying to add to it
                if ip in hidden_device_candidates:
                    # Add communication partners
                    for p in patterns:
                        if 'target' in p:
                            hidden_device_candidates[ip]['connections'].add(p['target'])

    def _get_hidden_devices_from_analysis(self, hidden_device_candidates: dict) -> List[dict]:
        """
        Determine which candidates are likely hidden devices.
        
        Args:
            hidden_device_candidates: Dictionary of candidate hidden devices
            
        Returns:
            List of hidden device information dictionaries
        """
        hidden_devices = []
        
        for ip, candidate in hidden_device_candidates.items():
            # Skip IPs that are in our known device list and not marked as hidden
            if ip in self.devices and not self.devices[ip].get('hidden', False):
                continue
            
            # Minimum confidence threshold
            if candidate['confidence'] >= 0.4:
                # Format protocols and connections for output
                protocols = list(candidate['protocols'])
                connections = list(candidate['connections'])
                evidence = candidate['evidence']
                
                hidden_devices.append({
                    'ip': ip,
                    'confidence': candidate['confidence'],
                    'evidence': evidence,
                    'protocols': protocols,
                    'connections': connections
                })
        
        # Sort by confidence, highest first
        hidden_devices.sort(key=lambda x: x['confidence'], reverse=True)
        
        return hidden_devices

    def _determine_protocol_for_connection(self, src_ip, dst_ip):
        """
        Determine the protocol used in communication between two IPs based on port.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            The protocol name or "Unknown"
        """
        protocol_counts = {}
        
        for comm in self.communications:
            if ((comm.get('ip') == dst_ip and comm.get('direction') == 'to') or
                (comm.get('ip') == src_ip and comm.get('direction') == 'from')):
                protocol = comm.get('protocol', 'Unknown')
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        if not protocol_counts:
            return "Unknown"
        
        # Return most common protocol
        return max(protocol_counts.items(), key=lambda x: x[1])[0]

    def analyze_pcaps_for_enhanced_topology(self) -> Tuple[Dict[str, List[str]], List[Dict[str, Any]]]:
        """
        Analyse PCAP files to discover connections and hidden devices.
        
        Returns:
            Tuple of (connections, hidden_devices)
        """
        self.logger.info("Analysing PCAP files for connections and hidden devices")
        
        # Find PCAP directory
        pcap_dir = os.path.join(self.results_dir, "pcap")
        if not os.path.exists(pcap_dir) or not os.path.isdir(pcap_dir):
            pcap_dir = self.results_dir
            if not os.path.exists(pcap_dir) or not os.path.isdir(pcap_dir):
                self.logger.error(f"No PCAP directory found")
                return {}, []
        
        # Check if scapy is available
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            has_scapy = True
        except ImportError:
            self.logger.error("Scapy is not available. Using basic PCAP analysis instead.")
            has_scapy = False
            
        # Find all pcap files
        pcap_files = []
        for root, _, files in os.walk(pcap_dir):
            for file in files:
                if file.endswith('.pcap'):
                    pcap_files.append(os.path.join(root, file))
        
        if not pcap_files:
            self.logger.error("No PCAP files found in directory")
            return {}, []
        
        # Dictionary to store discovered connections
        pcap_connections = defaultdict(set)
        
        # Dictionary to track hidden device activity
        hidden_device_candidates = {}
        traffic_patterns = defaultdict(list)
        raw_connections = []
        
        # Record the number of packets processed
        total_packets = 0
        connections_found = 0
        
        if has_scapy:
            # Process each PCAP file
            for pcap_file in pcap_files:
                try:
                    # Read PCAP file
                    packets = rdpcap(pcap_file)
                    file_packets = len(packets)
                    total_packets += file_packets
                    
                    # Process each packet
                    for packet in packets:
                        # Check for IP layer
                        if IP in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            
                            # Determine protocol and port
                            protocol = "Unknown"
                            src_port = None
                            dst_port = None
                            
                            if TCP in packet:
                                protocol = "TCP"
                                src_port = packet[TCP].sport
                                dst_port = packet[TCP].dport
                            elif UDP in packet:
                                protocol = "UDP"
                                src_port = packet[UDP].sport
                                dst_port = packet[UDP].dport
                            
                            # Try to identify industrial protocol based on port
                            if dst_port in self.known_protocols:
                                protocol = self.known_protocols[dst_port]
                            elif src_port in self.known_protocols:
                                protocol = self.known_protocols[src_port]
                            
                            # Record connection
                            if src_ip not in pcap_connections or dst_ip not in pcap_connections[src_ip]:
                                connections_found += 1
                            pcap_connections[src_ip].add(dst_ip)
                            
                            # Store detailed connection info
                            raw_connection = {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "protocol": protocol,
                                "timestamp": packet.time if hasattr(packet, 'time') else 0,
                                "size": len(packet)
                            }
                            raw_connections.append(raw_connection)
                            
                            # Record traffic pattern information for temporal analysis
                            if hasattr(packet, 'time'):
                                traffic_patterns[src_ip].append({
                                    'timestamp': packet.time,
                                    'target': dst_ip,
                                    'protocol': protocol,
                                    'size': len(packet),
                                    'port': dst_port
                                })
                            
                            # Check for hidden device signatures
                            self._analyze_packet_for_hidden_activity(
                                src_ip, dst_ip, protocol, packet, hidden_device_candidates
                            )
                except Exception as e:
                    self.logger.error(f"Error analyzing {pcap_file}: {e}")
        else:
            # If scapy is not available, use a simpler analysis approach
            self.logger.info("Using simple PCAP analysis based on simulation output")
            
            # Analyse the simulation output log entries as a basic PCAP substitute
            for comm in self.communications:
                src_ip = None
                dst_ip = comm.get('ip')
                protocol = comm.get('protocol', 'Unknown')
                
                # Determine direction
                if comm.get('direction') == 'to' and comm.get('action') == 'sent':
                    # Current device sent TO this IP
                    dst_ip = comm.get('ip')
                    src_ip = 'unknown'  # We don't know the source yet
                elif comm.get('direction') == 'from' and comm.get('action') == 'received':
                    # Current device received FROM this IP
                    src_ip = comm.get('ip')
                    dst_ip = 'unknown'  # We don't know the destination yet
                
                # Only record if we have both source and destination
                if src_ip and dst_ip and src_ip != 'unknown' and dst_ip != 'unknown':
                    pcap_connections[src_ip].add(dst_ip)
                    connections_found += 1
                
        # Enhanced traffic patterns analysis 
        self.analyze_traffic_patterns(traffic_patterns, hidden_device_candidates)
        
        # Process connections properly
        
        # Group connections by source-target pairs
        connection_pairs = defaultdict(int)
        connection_protocols = defaultdict(set)
        
        # First, aggregate all communications to find established connections
        for conn in raw_connections:
            src_ip = conn.get('src_ip')
            dst_ip = conn.get('dst_ip')
            protocol = conn.get('protocol', 'Unknown')
            
            # Skip broadcast addresses and multicast
            if (not src_ip or not dst_ip or 
                dst_ip.startswith('255.') or 
                dst_ip.startswith('224.') or 
                dst_ip == '255.255.255.255'):
                continue
            
            # Skip local addresses
            if dst_ip == '127.0.0.1' or src_ip == '127.0.0.1':
                continue
                
            conn_key = f"{src_ip}_{dst_ip}"
            connection_pairs[conn_key] += 1
            connection_protocols[conn_key].add(protocol)
        
        for conn_key, count in connection_pairs.items():
            if count < 3: # Skip 0-2 length packets (Optional)
                continue
                
            src_ip, dst_ip = conn_key.split('_')
            
            # Get dominant protocol
            protocols = list(connection_protocols[conn_key])
            protocol = protocols[0] if protocols else "Unknown"
            
            # Add source to comprehensive results if not present
            if src_ip not in self.comprehensive_results:
                self.comprehensive_results[src_ip] = {"connections": [], "detection_info": {}}
            
            # Check if this connection already exists
            connection_exists = False
            for existing_conn in self.comprehensive_results[src_ip]["connections"]:
                if isinstance(existing_conn, dict) and existing_conn.get("target") == dst_ip:
                    connection_exists = True
                    break
            
            # Add connection if it doesn't exist
            if not connection_exists:
                # Store the connection with target IP and metadata
                self.comprehensive_results[src_ip]["connections"].append({
                    "target": dst_ip,
                    "confidence": min(0.5 + (count * 0.02), 0.95),  # Higher confidence for more packets
                    "protocol": protocol
                })
        
        # Convert sets to lists for JSON serialization
        connections = {src: list(targets) for src, targets in pcap_connections.items()}
        
        # Get list of hidden devices from analysis
        hidden_devices = self._get_hidden_devices_from_analysis(hidden_device_candidates)
        
        self.logger.info(f"Processed {total_packets} total packets")
        self.logger.info(f"Found {connections_found} unique connections between devices")
        
        # Add hidden devices to comprehensive results
        for device in hidden_devices:
            ip = device["ip"]
            if ip not in self.comprehensive_results:
                self.comprehensive_results[ip] = {"connections": [], "detection_info": {}}
            
            self.comprehensive_results[ip]["detection_info"]["pcap_hidden_device"] = {
                "confidence": device["confidence"],
                "evidence": device["evidence"],
                "protocols": device.get("protocols", []),
                "pattern": device.get("pattern", "Unknown")
            }
        
        return connections, hidden_devices