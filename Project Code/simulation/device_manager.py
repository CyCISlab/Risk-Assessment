"""
Device Manager for ICS Simulations

Manages device creation, attributes, and application setup
for industrial control system simulations.
"""

import random
from typing import Dict, Any, Optional

class DeviceManager:
    """Manages device creation and configuration."""
    
    def __init__(self, ns, network_builder, randomize: bool = False, seed: Optional[int] = None) -> None:
        """
        Initialise device manager.
        
        Args:
            ns: NS3 module instance
            network_builder: NetworkBuilder instance
            randomize: Whether to enable randomisation in simulation
            seed: Random seed for reproducibility
        """
        self.ns = ns
        self.network_builder = network_builder
        self.applications: Dict[str, Dict] = {}
        self.device_info: Dict[str, Dict] = {}
        
        # Randomisation settings
        self.randomize = randomize
        if randomize:
            if seed is not None:
                random.seed(seed)
            self.seed = seed

    def create_broadcast_client(self, name: str, node_container: str, node_index: int,
                            target_port: int, max_packets: int = 10, interval: float = 10.0,
                            packet_size: int = 128, start_time: float = 1.0, 
                            stop_time: float = 300.0) -> Any:
        """
        Create broadcast UDP client on device.
        """
        # Generate broadcast address string
        broadcast_address = "255.255.255.255"  # Global broadcast
        
        # Randomise timing if enabled
        if self.randomize:
            start_time = max(0.1, start_time + random.uniform(-1.0, 1.0))
            interval = interval * random.uniform(0.9, 1.1)
        
        # Create an Address object first
        address = self.ns.InetSocketAddress(
            self.ns.Ipv4Address(broadcast_address), 
            target_port
        ).ConvertTo()
        
        # Create client helper with the address object
        client_helper = self.ns.UdpEchoClientHelper(address)
        
        client_helper.SetAttribute("MaxPackets", self.ns.UintegerValue(max_packets))
        client_helper.SetAttribute("Interval", self.ns.TimeValue(self.ns.Seconds(interval)))
        client_helper.SetAttribute("PacketSize", self.ns.UintegerValue(packet_size))
        
        node = self.network_builder.get_node(node_container, node_index)
        
        # Install application
        client_apps = client_helper.Install(node)
        client_apps.Start(self.ns.Seconds(start_time))
        client_apps.Stop(self.ns.Seconds(stop_time))
        
        # Store for reference
        self.applications[name] = {
            "type": "broadcast_client",
            "apps": client_apps,
            "target_address": broadcast_address,
            "target_port": target_port,
            "max_packets": max_packets,
            "interval": interval,
            "packet_size": packet_size,
            "node_container": node_container,
            "node_index": node_index
        }
        
        # Store device info
        self._add_device_info(node_container, node_index, "clients", {
            "name": name,
            "target_address": broadcast_address + " (broadcast)",
            "target_port": target_port
        })
        
        return client_apps

    def create_server(self, name: str, node_container: str, node_index: int, 
                     port: int, start_time: float = 1.0, stop_time: float = 300.0) -> Any:
        """
        Create UDP echo server on device.
        
        Args:
            name: Name for server
            node_container: Name of node container
            node_index: Index of node in container
            port: Port number to listen on
            start_time: When to start server (seconds)
            stop_time: When to stop server (seconds)
            
        Returns:
            Server application
        """
        # Randomise start time if enabled
        if self.randomize:
            start_time = max(0.1, start_time + random.uniform(-0.5, 0.5))
            
            # Randomly vary port for non-standard ports
            if port not in [502, 20000, 47808, 22] and random.random() < 0.15:
                port = port + random.randint(-5, 5)
        
        # Create server helper
        server_helper = self.ns.UdpEchoServerHelper(port)
        
        # Get node to install on
        node = self.network_builder.get_node(node_container, node_index)
        
        # Install application
        server_apps = server_helper.Install(node)
        server_apps.Start(self.ns.Seconds(start_time))
        server_apps.Stop(self.ns.Seconds(stop_time))
        
        # Store for reference
        self.applications[name] = {
            "type": "server",
            "apps": server_apps,
            "port": port,
            "node_container": node_container,
            "node_index": node_index
        }
        
        # Store device info
        self._add_device_info(node_container, node_index, "servers", {"name": name, "port": port})
        
        return server_apps
    
    def create_client(self, name: str, node_container: str, node_index: int,
                     target_address: str, target_port: int, 
                     max_packets: int = 100, interval: float = 1.0,
                     packet_size: int = 64, start_time: float = 2.0, 
                     stop_time: float = 300.0) -> Any:
        """
        Create UDP echo client on device.
        
        Args:
            name: Name for client
            node_container: Name of node container
            node_index: Index of node in container
            target_address: Target IP address
            target_port: Target port
            max_packets: Maximum number of packets to send
            interval: Interval between packets (seconds)
            packet_size: Size of packets (bytes)
            start_time: When to start client (seconds)
            stop_time: When to stop client (seconds)
            
        Returns:
            Client application
        """
        if self.randomize:
            # Randomise timing
            start_time = max(0.1, start_time + random.uniform(-0.7, 0.7))
            
            # Randomise interval for realistic traffic
            interval = interval * random.uniform(0.8, 1.2)
            
            # Randomise packet size
            packet_size = int(packet_size * random.uniform(0.9, 1.1))
            
            # Add occasional packet bursts
            if random.random() < 0.2:
                max_packets = max_packets + random.randint(5, 20)
                interval = interval * 0.7
        
        # Create client helper
        client_helper = self.ns.UdpEchoClientHelper(target_address, target_port)
        client_helper.SetAttribute("MaxPackets", self.ns.UintegerValue(max_packets))
        client_helper.SetAttribute("Interval", self.ns.TimeValue(self.ns.Seconds(interval)))
        client_helper.SetAttribute("PacketSize", self.ns.UintegerValue(packet_size))
        
        node = self.network_builder.get_node(node_container, node_index)
        
        # Install application
        client_apps = client_helper.Install(node)
        client_apps.Start(self.ns.Seconds(start_time))
        client_apps.Stop(self.ns.Seconds(stop_time))
        
        # Store for reference
        self.applications[name] = {
            "type": "client",
            "apps": client_apps,
            "target_address": target_address,
            "target_port": target_port,
            "max_packets": max_packets,
            "interval": interval,
            "packet_size": packet_size,
            "node_container": node_container,
            "node_index": node_index
        }
        
        # Store device info
        self._add_device_info(node_container, node_index, "clients", {
            "name": name,
            "target_address": target_address,
            "target_port": target_port
        })
        
        return client_apps
    
    def create_one_time_client(self, name: str, node_container: str, node_index: int,
                             target_address: str, target_port: int,
                             packet_size: int = 64, start_time: float = 0.0,
                             duration: float = 1.0) -> Any:
        """
        Create one-time UDP echo client that sends packets within specific time window.
        
        Args:
            name: Name for client
            node_container: Name of node container
            node_index: Index of node in container
            target_address: Target IP address
            target_port: Target port number
            packet_size: Size of packets (bytes)
            start_time: When to start client (seconds)
            duration: How long to run (seconds)
            
        Returns:
            Client application
        """
        # Randomise one-time events if enabled
        if self.randomize:
            start_time = max(0.1, start_time + random.uniform(-1.0, 1.0))
            duration = duration * random.uniform(0.8, 1.5)
            
            max_packets = 1
            interval = 0.1
            
            # Occasionally multiple packets
            if random.random() < 0.3:
                max_packets = random.randint(2, 5)
        else:
            max_packets = 1
            interval = 0.1
        
        return self.create_client(
            name=name,
            node_container=node_container,
            node_index=node_index,
            target_address=target_address,
            target_port=target_port,
            max_packets=max_packets,
            interval=interval,
            packet_size=packet_size,
            start_time=start_time,
            stop_time=start_time + duration
        )
    
    def get_interface_address(self, interface_name: str, device_index: int) -> str:
        """
        Get IP address of interface.
        
        Args:
            interface_name: Name of interface
            device_index: Device index in interface
            
        Returns:
            IP address as string
        """
        return self.network_builder.get_interface_address(interface_name, device_index)
    
    def get_network_builder(self):
        """Get network builder instance."""
        return self.network_builder
    
    def print_device_summary(self) -> None:
        """Print summary of all devices and their applications."""
        print("\nDEVICE SUMMARY:")
        for device_key, info in self.device_info.items():
            container, index = device_key.split('_')
            print(f"Device {container}[{index}]:")
            
            if info["servers"]:
                print("  Servers:")
                for server in info["servers"]:
                    print(f"    - {server['name']} (port {server['port']})")
            
            if info["clients"]:
                print("  Clients:")
                for client in info["clients"]:
                    print(f"    - {client['name']} -> {client['target_address']}:{client['target_port']}")
            
            print()
    
    def _add_device_info(self, node_container: str, node_index: int, info_type: str, info: Dict) -> None:
        """Add information about device application."""
        device_key = f"{node_container}_{node_index}"
        if device_key not in self.device_info:
            self.device_info[device_key] = {
                "servers": [],
                "clients": []
            }
        self.device_info[device_key][info_type].append(info)