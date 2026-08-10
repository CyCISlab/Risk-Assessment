"""
Application Manager for ICS Simulations

Provides high-level functions for setting up ICS applications
and communication patterns.
"""

import random
import logging
from typing import Dict, List

# Constants
STANDARD_PROTOCOLS = [502, 20000, 47808, 22]
EXTRA_NODES_PROBABILITY = 0.3
VENDOR_CONNECTION_PROBABILITY = 0.7
IT_TO_OT_ATTEMPT_PROBABILITY = 0.3
PACKET_BURST_PROBABILITY = 0.2

class ApplicationManager:
    """Manages application setup and communication patterns."""
    
    def __init__(self, ns, device_manager) -> None:
        """
        Initialise application manager.
        
        Args:
            ns: NS3 module instance
            device_manager: DeviceManager instance
        """
        self.ns = ns
        self.device_manager = device_manager
        self.protocol_ports: Dict[str, int] = {}
        self.logger = logging.getLogger(__name__)
        
        # Get randomisation settings from device manager
        self.randomize = getattr(device_manager, 'randomize', False)
    
    def register_protocol_ports(self, protocols: Dict[str, int]) -> None:
        """
        Register protocol ports for simulation.
        
        Args:
            protocols: Dictionary mapping protocol names to port numbers
        """
        self.protocol_ports = protocols
    
    def setup_standard_control_network(self, simulation_time: float) -> None:
        """
        Set up applications for standard control network with realistic protocol behaviors.
        
        Args:
            simulation_time: Simulation duration in seconds
        """
        self.logger.info("Setting up standard control network with enhanced protocol behaviors")
        
        # Create Modbus servers on PLCs with protocol-specific behaviors
        self._create_plc_servers(simulation_time)
        
        # Set up HMI polling to PLCs with realistic patterns
        self._setup_realistic_hmi_communication(simulation_time)
        
        # Add engineering workstation communications
        self._create_engineering_workstation_traffic(simulation_time)
        
        # Add PLC-to-PLC communications
        self._create_plc_to_plc_traffic(simulation_time)
        
        # Add spontaneous messages (alarms, events)
        self._setup_spontaneous_events(simulation_time)
        
        # Add broadcast discovery messages that happen periodically
        self._setup_broadcast_discovery(simulation_time)

    def _setup_broadcast_discovery(self, simulation_time: float) -> None:
        """Add periodic broadcast discovery messages."""
        if not self.randomize:
            return
        
        # HMI broadcasts discovery messages
        start_time = 15.0  # Start after network is established
        
        # Use a prime number for interval to avoid sync issues
        interval = 23.0
        
        # Calculate number of packets
        max_packets = int((simulation_time - start_time) / interval) + 1
        
        self.device_manager.create_broadcast_client(
            name="hmi_discovery",
            node_container="otControlNodes",
            node_index=0,  # HMI
            target_port=self.protocol_ports["bacnet_port"],
            max_packets=max_packets,
            interval=interval,
            packet_size=128,
            start_time=start_time,
            stop_time=simulation_time
        )

    def _create_plc_to_plc_traffic(self, simulation_time: float) -> None:
        """Add PLC-to-PLC communications."""
        # PLC1 to PLC2 communication
        self._create_polling_client(
            "plc1_to_plc2",
            "otControlNodes", 2,  # PLC1
            self.device_manager.get_interface_address("otControl", 3),  # PLC2
            self.protocol_ports["modbus_port"],
            simulation_time,
            interval=4.0,
            packet_size=48
        )
        
        # PLC2 to PLC3 communication
        self._create_polling_client(
            "plc2_to_plc3",
            "otControlNodes", 3,  # PLC2
            self.device_manager.get_interface_address("otControl", 4),  # PLC3
            self.protocol_ports["dnp3_port"],
            simulation_time,
            interval=5.0,
            packet_size=64
        )
    def _create_engineering_workstation_traffic(self, simulation_time: float) -> None:
        """Add engineering workstation communications to the simulation."""
        # EWS to PLC1 for configuration/programming
        self._create_polling_client(
            "ews_to_plc1",
            "otControlNodes", 1,  # Engineering Workstation
            self.device_manager.get_interface_address("otControl", 2),  # PLC1
            self.protocol_ports["modbus_port"],
            simulation_time,
            interval=10.0,  # Less frequent than HMI
            packet_size=128  # Larger packets for configuration
        )
        
        # EWS to PLC2 occasional check
        if self.randomize:
            self._create_sporadic_client(
                "ews_to_plc2_check",
                "otControlNodes", 1,  # Engineering Workstation
                self.device_manager.get_interface_address("otControl", 3),  # PLC2
                self.protocol_ports["modbus_port"],
                simulation_time,
                interval=30.0,
                packet_size=96,
                occurrence_probability=0.6
            )


    def _create_plc_servers(self, simulation_time: float) -> None:
        """Create Modbus TCP servers on PLCs with realistic protocol behavior."""
        # Modbus servers on PLC1 and PLC2
        for i, plc_name in enumerate(["modbus_plc1", "modbus_plc2"], start=2):
            self._create_server(plc_name, "otControlNodes", i,
                            self.protocol_ports["modbus_port"],
                            simulation_time)
        
        # DNP3 server on PLC3
        self._create_server("dnp3_plc3", "otControlNodes", 4,
                        self.protocol_ports["dnp3_port"],
                        simulation_time)
    
    def setup_edge_network_applications(self, simulation_time: float, 
                                      edge_gateway_addr: str, 
                                      serial_device_addr: str, 
                                      maintenance_addr: str, 
                                      hidden_backup_addr: str) -> None:
        """
        Set up applications for edge/hidden network.
        
        Args:
            simulation_time: Simulation duration in seconds
            edge_gateway_addr: IP address of edge gateway
            serial_device_addr: IP address of serial device
            maintenance_addr: IP address of maintenance server
            hidden_backup_addr: IP address of hidden backup device
        """
        # Core edge network servers
        self._setup_edge_servers(simulation_time)
        
        # Set up DNP3 communication through edge gateway
        self._setup_edge_communications(simulation_time, edge_gateway_addr)
        
        # Hidden device communications
        self._setup_hidden_communications(simulation_time, hidden_backup_addr)
        
        # Maintenance connections
        self._setup_maintenance_connections(simulation_time)
        
        # Cross-network communications
        self._setup_cross_network_communications(simulation_time)
        
        # Random intermittent communications
        if self.randomize:
            self._setup_random_communications(simulation_time, maintenance_addr)
    
    def setup_hidden_process_devices(self, simulation_time: float, 
                                   serial_device_addr: str, 
                                   hidden_backup_addr: str) -> None:
        """
        Set up hidden and silent devices in process network.
        
        Args:
            simulation_time: Simulation duration in seconds
            serial_device_addr: IP address of serial device
            hidden_backup_addr: IP address of hidden backup device
        """
        # Hidden device servers
        self._create_server("legacy_proprietary", "otProcessNodes", 0, 
                           self.protocol_ports["proprietary_port"], simulation_time)
        
        self._create_server("silent_sensor", "otProcessNodes", 1, 
                           self.protocol_ports["modbus_port"], simulation_time)
        
        self._create_server("serial_device", "otProcessNodes", 2, 
                           self.protocol_ports["proprietary_port"], simulation_time)
        
        self._create_server("hidden_backup", "otProcessNodes", 3, 
                           self.protocol_ports["bacnet_port"], simulation_time)
        
        # Rare communications between hidden devices
        if self.randomize:
            self._setup_hidden_device_communications(simulation_time)
    
    def _create_server(self, name: str, node_container: str, node_index: int, 
                      port: int, simulation_time: float) -> None:
        """Helper method to create server with standard timing."""
        self.device_manager.create_server(
            name=name,
            node_container=node_container,
            node_index=node_index,
            port=port,
            stop_time=simulation_time
        )
    
    def _setup_realistic_hmi_communication(self, simulation_time: float) -> None:
        """Set up HMI polling to PLCs with realistic traffic patterns."""
        # Set up polling with different intervals for different protocols
        plc_configs = [
            {"name": "hmi_poll_plc1", "index": 2, "port": "modbus_port", "interval": 2.0, "packet_size": 64},
            {"name": "hmi_poll_plc2", "index": 3, "port": "modbus_port", "interval": 3.0, "packet_size": 64},
            {"name": "hmi_poll_plc3", "index": 4, "port": "dnp3_port", "interval": 5.0, "packet_size": 64}
        ]
        
        for config in plc_configs:
            # Create regular polling
            self._create_polling_client(
                config["name"], 
                "otControlNodes", 0,  # HMI
                self.device_manager.get_interface_address("otControl", config["index"]),
                self.protocol_ports[config["port"]],
                simulation_time,
                interval=config["interval"],
                packet_size=config["packet_size"]
            )

    def _setup_spontaneous_events(self, simulation_time: float) -> None:
        """Add spontaneous messages (alarms, events)."""
        if not self.randomize:
            return
            
        num_events = random.randint(3, 8)
        
        for i in range(num_events):
            source_index = random.randint(2, 4)  # PLC1, PLC2, or PLC3
            start_time = random.uniform(10, simulation_time * 0.8)
            port = (self.protocol_ports["modbus_port"] if source_index < 4 
                   else self.protocol_ports["dnp3_port"])
            
            self.device_manager.create_one_time_client(
                name=f"plc_event_{i}",
                node_container="otControlNodes",
                node_index=source_index,
                target_address=self.device_manager.get_interface_address("otControl", 0),
                target_port=port,
                packet_size=random.randint(100, 250),
                start_time=start_time,
                duration=random.uniform(0.5, 2.0)
            )
    
    def _setup_edge_servers(self, simulation_time: float) -> None:
        """Set up edge network servers."""
        self._create_server("edge_gateway", "dmzNodes", 1, 
                           self.protocol_ports["edge_gateway_port"], simulation_time)
        
        self._create_server("scada_dnp3", "otControlNodes", 0, 
                           self.protocol_ports["dnp3_port"], simulation_time)
        
        self._create_server("legacy_firmware", "otProcessNodes", 0, 
                           self.protocol_ports["firmware_update_port"], simulation_time)
    
    def _setup_edge_communications(self, simulation_time: float, edge_gateway_addr: str) -> None:
        """Set up edge gateway communications with timing patterns."""
        # Control PLC to edge gateway communication - use distinct timing pattern
        self._create_polling_client(
            "plc_to_edge",
            "otControlNodes", 3,  # Control PLC
            edge_gateway_addr,
            self.protocol_ports["edge_gateway_port"],
            simulation_time,
            interval=3.0,  # Use prime number interval for distinction
            packet_size=128
        )
        
        # Edge gateway to SCADA communication - use different timing pattern
        self._create_polling_client(
            "edge_to_scada",
            "dmzNodes", 1,  # Edge Gateway
            self.device_manager.get_network_builder().get_interface_address("otControl", 0),
            self.protocol_ports["modbus_port"],
            simulation_time,
            interval=7.0,  # Different prime number interval 
            packet_size=64
        )
    
    def _setup_hidden_communications(self, simulation_time: float, hidden_backup_addr: str) -> None:
        """Set up hidden sensor communications."""
        self._create_polling_client(
            "hidden_sensor_comm",
            "otProcessNodes", 1,  # Hidden Sensor 1
            self.device_manager.get_interface_address("otProcess", 2),  # Hidden Sensor 2
            self.protocol_ports["proprietary_port"],
            simulation_time,
            interval=5.0,
            packet_size=64
        )
        
        self._create_polling_client(
            "backup_comm",
            "otProcessNodes", 3,  # Serial Gateway
            hidden_backup_addr,
            self.protocol_ports["bacnet_port"],
            simulation_time,
            interval=15.0,
            packet_size=32
        )
    
    def _setup_maintenance_connections(self, simulation_time: float) -> None:
        """Set up maintenance connections."""
        self._create_polling_client(
            "maintenance_check",
            "maintenanceNodes", 0,  # Maintenance Server
            self.device_manager.get_interface_address("otProcess", 0),  # Legacy PLC
            self.protocol_ports["firmware_update_port"],
            simulation_time,
            interval=30.0,
            packet_size=256
        )
    
    def _setup_cross_network_communications(self, simulation_time: float) -> None:
        """Set up cross-network communications."""
        self._create_polling_client(
            "control_to_process",
            "otControlNodes", 3,  # Control PLC
            self.device_manager.get_network_builder().get_interface_address("otProcess", 0),
            self.protocol_ports["modbus_port"],
            simulation_time,
            interval=5.0,
            packet_size=96
        )
    
    def _setup_random_communications(self, simulation_time: float, maintenance_addr: str) -> None:
        """Set up random intermittent communications."""
        if random.random() < VENDOR_CONNECTION_PROBABILITY:
            self._create_sporadic_client(
                "vendor_diagnostics",
                "maintenanceNodes", 1,  # Vendor Connection
                maintenance_addr,
                self.protocol_ports["maintenance_port"],
                simulation_time,
                interval=45.0,
                packet_size=320,
                occurrence_probability=0.4
            )
        
        if random.random() < IT_TO_OT_ATTEMPT_PROBABILITY:
            self._create_sporadic_client(
                "it_to_ot_attempt",
                "itNodes", 0,  # Corporate Firewall
                self.device_manager.get_interface_address("otControl", 0),  # HMI
                self.protocol_ports["modbus_port"],
                simulation_time,
                interval=60.0,
                packet_size=128,
                occurrence_probability=0.2
            )
    
    def _setup_hidden_device_communications(self, simulation_time: float) -> None:
        """Set up rare communications between hidden devices."""
        for i in range(random.randint(1, 3)):
            source_index = random.randint(0, 3)
            target_index = random.randint(0, 3)
            
            # Avoid self-communication
            if source_index == target_index:
                continue
            
            self._create_sporadic_client(
                f"hidden_comm_{i}",
                "otProcessNodes", source_index,
                self.device_manager.get_interface_address("otProcess", target_index),
                self.protocol_ports["proprietary_port"],
                simulation_time,
                interval=random.uniform(20.0, 120.0),
                packet_size=random.randint(32, 64),
                occurrence_probability=0.3
            )
    
    def _create_polling_client(self, name: str, node_container: str, node_index: int,
                             target_address: str, target_port: int,
                             simulation_time: float, interval: float = 5.0,
                             packet_size: int = 64) -> None:
        """
        Create polling client that regularly communicates with server.
        
        Args:
            name: Name for client
            node_container: Name of node container
            node_index: Index of node in container
            target_address: Target IP address
            target_port: Target port number
            simulation_time: Total simulation time
            interval: Polling interval in seconds
            packet_size: Size of packets in bytes
        """
        # Calculate number of packets with margin
        max_packets = int((simulation_time / interval) * 1.1) + 5
        
        self.device_manager.create_client(
            name=name,
            node_container=node_container,
            node_index=node_index,
            target_address=target_address,
            target_port=target_port,
            max_packets=max_packets,
            interval=interval,
            packet_size=packet_size,
            start_time=2.0,
            stop_time=simulation_time
        )
    
    def _create_sporadic_client(self, name: str, node_container: str, node_index: int,
                              target_address: str, target_port: int,
                              simulation_time: float, interval: float = 30.0,
                              packet_size: int = 64, occurrence_probability: float = 0.5) -> None:
        """
        Create sporadic client that occasionally sends messages.
        
        Args:
            name: Name for client
            node_container: Name of node container
            node_index: Index of node in container
            target_address: Target IP address
            target_port: Target port number
            simulation_time: Total simulation time
            interval: Average interval between occurrences
            packet_size: Size of packets in bytes
            occurrence_probability: Probability of communication occurring
        """
        # Only create if probability check passes
        if random.random() > occurrence_probability:
            return
        
        # Random timing and packet count
        max_packets = random.randint(1, 3)
        start_time = random.uniform(simulation_time * 0.1, simulation_time * 0.7)
        
        self.device_manager.create_client(
            name=name,
            node_container=node_container,
            node_index=node_index,
            target_address=target_address,
            target_port=target_port,
            max_packets=max_packets,
            interval=interval,
            packet_size=packet_size,
            start_time=start_time,
            stop_time=min(start_time + (interval * max_packets * 1.2), simulation_time)
        )