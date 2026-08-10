"""
Network Builder for ICS Simulations

Provides abstractions for building network topologies and connections 
in industrial control system simulations.
"""

import os
import random
from typing import Any, Dict, Set, Tuple, Optional

class NetworkBuilder:
    """Manages creation of network segments and connections."""
    
    def __init__(self, ns, randomize: bool = False, seed: Optional[int] = None) -> None:
        """
        Initialise network builder.
        
        Args:
            ns: NS3 module
            randomize: Enable network randomisation
            seed: Reproducibility seed
        """
        self.ns = ns
        self.node_containers: Dict[str, Any] = {}
        self.csma_networks: Dict[str, Dict] = {}
        self.p2p_connections: Dict[str, Dict] = {}
        self.interfaces: Dict[str, Any] = {}
        self.assigned_subnets: Set[str] = set()
        
        # Configure randomisation
        self.randomize = randomize
        self.seed = seed
        
        if randomize:
            seed_value = seed if seed is not None else random.randint(1, 10000)
            random.seed(seed_value)
            self.seed = seed_value
    
    def create_nodes(self, segment_name: str, count: int) -> Any:
        """
        Create node container.
        
        Args:
            segment_name: Network segment name
            count: Initial node count
            
        Returns:
            Node container
        """
        # Occasionally add extra nodes in hidden segments
        if self.randomize and segment_name in ["otProcessNodes", "maintenanceNodes"]:
            if random.random() < 0.3:  # 30% chance
                count += random.randint(1, 2)
        
        nodes = self.ns.NodeContainer()
        nodes.Create(count)
        self.node_containers[segment_name] = nodes
        return nodes
    
    def create_p2p_link(self, name: str, source_container: str, source_index: int, 
                       target_container: str, target_index: int, 
                       data_rate: str = "10Mbps", delay: str = "2ms") -> Tuple[Any, Any]:
        """
        Create point-to-point link between nodes.
        
        Args:
            name: Connection name
            source_container: Source node container
            source_index: Source node index
            target_container: Target node container
            target_index: Target node index
            data_rate: Link bandwidth
            delay: Network delay
            
        Returns:
            Connection and device containers
        """
        # Randomise link characteristics if enabled
        if self.randomize:
            data_rate = self._randomize_data_rate(data_rate, name)
            delay = self._randomize_delay(delay)
        
        # Create point-to-point connection
        p2p_helper = self.ns.PointToPointHelper()
        p2p_helper.SetDeviceAttribute("DataRate", self.ns.StringValue(data_rate))
        p2p_helper.SetChannelAttribute("Delay", self.ns.StringValue(delay))
        
        # Prepare connection container
        connection = self.ns.NodeContainer()
        connection.Add(self.node_containers[source_container].Get(source_index))
        connection.Add(self.node_containers[target_container].Get(target_index))
        
        # Install devices
        devices = p2p_helper.Install(connection)
        
        # Store connection details
        self.p2p_connections[name] = {
            "container": connection,
            "devices": devices,
            "helper": p2p_helper,
            "data_rate": data_rate,
            "delay": delay
        }
        
        return connection, devices
    
    def create_csma_network(self, name: str, container_name: str, 
                           data_rate: str = "100Mbps", delay: int = 6560) -> Any:
        """
        Create CSMA bus network.
        
        Args:
            name: Network name
            container_name: Node container
            data_rate: Network bandwidth
            delay: Network delay
            
        Returns:
            CSMA network devices
        """
        # Randomise network characteristics if enabled
        if self.randomize:
            data_rate = self._randomize_data_rate(data_rate, name)
            delay = int(delay * random.uniform(0.9, 1.4))
        
        # Create CSMA network
        csma_helper = self.ns.CsmaHelper()
        csma_helper.SetChannelAttribute("DataRate", self.ns.StringValue(data_rate))
        csma_helper.SetChannelAttribute("Delay", self.ns.TimeValue(self.ns.NanoSeconds(delay)))
        
        # Install devices
        devices = csma_helper.Install(self.node_containers[container_name])
        
        # Store network details
        self.csma_networks[name] = {
            "devices": devices,
            "helper": csma_helper,
            "data_rate": data_rate,
            "delay": delay
        }
        
        return devices
    
    def assign_ip_addresses(self, name: str, devices: Any, network: str, 
                          netmask: str = "255.255.255.0") -> Any:
        """
        Assign IP addresses to network devices.
        
        Args:
            name: Interface name
            devices: Device container
            network: Base network address
            netmask: Network mask
            
        Returns:
            Assigned interface container
        """
        safe_network = self._get_safe_subnet(network)
        
        address_helper = self.ns.Ipv4AddressHelper()
        address_helper.SetBase(self.ns.Ipv4Address(safe_network), self.ns.Ipv4Mask(netmask))
        
        interfaces = address_helper.Assign(devices)
        self.interfaces[name] = interfaces
        
        return interfaces
    
    def enable_pcap(self, pcap_dir: str, prefix: str = "ics-simulation") -> None:
        """
        Enable packet capture on all networks.
        
        Args:
            pcap_dir: PCAP storage directory
            prefix: PCAP filename prefix
        """
        # Capture point-to-point links
        for name, p2p in self.p2p_connections.items():
            p2p["helper"].EnablePcapAll(os.path.join(pcap_dir, prefix))
        
        # Capture CSMA networks
        for name, csma in self.csma_networks.items():
            csma["helper"].EnablePcap(os.path.join(pcap_dir, f"ics-{name}"), 
                                     csma["devices"].Get(0), True)
    
    def get_node(self, container_name: str, index: int) -> Any:
        """
        Retrieve specific node from container.
        
        Args:
            container_name: Container name
            index: Node index
            
        Returns:
            Node object
        """
        return self.node_containers[container_name].Get(index)
    
    def get_interface_address(self, interface_name: str, index: int) -> str:
        """
        Get IP address of specific interface.
        
        Args:
            interface_name: Interface name
            index: Interface index
            
        Returns:
            IP address string
        """
        return self.interfaces[interface_name].GetAddress(index).ConvertTo()
    
    def _randomize_data_rate(self, data_rate: str, name: str) -> str:
        """Randomise data rate based on network type."""
        data_rate_value = int(data_rate.replace("Mbps", ""))
        
        # Adjust based on network segment
        if "control" in name.lower():
            data_rate_value = int(data_rate_value * random.uniform(0.9, 1.1))
        elif "process" in name.lower():
            data_rate_value = int(data_rate_value * random.uniform(0.75, 1.05))
        else:
            data_rate_value = int(data_rate_value * random.uniform(0.8, 1.2))
        
        return f"{data_rate_value}Mbps"
    
    def _randomize_delay(self, delay: str) -> str:
        """Randomise network delay with occasional spikes."""
        delay_value = int(delay.replace("ms", ""))
        delay_value = int(delay_value * random.uniform(0.9, 1.5))
        
        # Occasional high-latency links
        if random.random() < 0.1:
            delay_value = int(delay_value * random.uniform(1.5, 2.5))
        
        return f"{delay_value}ms"
    
    def _get_safe_subnet(self, proposed_network: str) -> str:
        """
        Ensure unique subnet allocation.
        
        Args:
            proposed_network: Original subnet
            
        Returns:
            Conflict-free subnet
        """
        base_subnet = '.'.join(proposed_network.split('.')[:3])
        
        # If this base subnet is already used, find alternative
        if base_subnet in self.assigned_subnets:
            for offset in range(1, 20):
                new_third_octet = (int(base_subnet.split('.')[2]) + offset) % 256
                new_subnet = f"{base_subnet.split('.')[0]}.{base_subnet.split('.')[1]}.{new_third_octet}.0"
                new_base = '.'.join(new_subnet.split('.')[:3])
                
                if new_base not in self.assigned_subnets:
                    self.assigned_subnets.add(new_base)
                    return new_subnet
        
        # Use original subnet if no collision
        self.assigned_subnets.add(base_subnet)
        return proposed_network