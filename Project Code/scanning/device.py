"""
Device Module

Defines the Device class used to represent network devices in vulnerability assessments.
Provides consistent interface for accessing device properties and attributes.
"""

from typing import Any, List, Set


class Device:
    """
    Represents a network device with its attributes.
    
    Provides a consistent interface for retrieving device properties
    and handling additional attributes. Supports checking whether a 
    device is categorized as hidden, silent, or edge.
    
    Attributes:
        ip: IP address of the device
        device_type: Type of device (e.g., PLC, HMI, Router)
        network: Network segment the device belongs to
        hidden: Whether the device is categorized as hidden
    """
    
    def __init__(self, ip: str, device_type: str, network: str, hidden: bool = False):
        """
        Initialize a device with its basic properties.
        
        Args:
            ip: IP address of the device
            device_type: Type of device (e.g., PLC, HMI, Router)
            network: Network segment the device belongs to
            hidden: Whether the device is categorized as hidden
        """
        self.ip = ip
        self.device_type = device_type
        self.type = device_type  # For backwards compatibility
        self.network = network
        self.hidden = hidden
        self.attributes = {}
        
        # Track protocols the device supports
        self.protocols = set()
    
    def add_attribute(self, key: str, value: Any) -> None:
        """
        Add or update an attribute for this device.
        
        Args:
            key: Attribute name
            value: Attribute value
        """
        self.attributes[key] = value
        
        # Special handling for protocol attributes
        if key == 'protocol' or key == 'port':
            self.protocols.add(str(value))
    
    def get_attribute(self, key: str, default: Any = None) -> Any:
        """
        Get an attribute value with an optional default.
        
        Args:
            key: Attribute name
            default: Default value if attribute doesn't exist
            
        Returns:
            Attribute value or default
        """
        return self.attributes.get(key, default)
    
    def add_protocol(self, protocol: str) -> None:
        """
        Add a supported protocol to this device.
        
        Args:
            protocol: Protocol identifier (e.g. "502" for Modbus)
        """
        self.protocols.add(protocol)
        
    def get_protocols(self) -> Set[str]:
        """
        Get the set of protocols supported by this device.
        
        Returns:
            Set of protocol identifiers
        """
        return self.protocols
    
    def supports_protocol(self, protocol: str) -> bool:
        """
        Check if device supports a specific protocol.
        
        Args:
            protocol: Protocol identifier to check
            
        Returns:
            True if device supports the protocol, False otherwise
        """
        return protocol in self.protocols
    
    def potential_edge_device(self) -> bool:
        """
        Determine if this device is an edge device.
        
        Returns:
            True if device is an edge device, False otherwise
        """
        lower_type = self.device_type.lower()
        lower_network = self.network.lower()
        
        # Check device type keywords
        type_keywords = ['edge', 'gateway', 'bridge', 'protocol converter']
        network_keywords = ['dmz', 'boundary']
        
        # Edge device conditions:
        # 1. Type contains edge-related keywords
        has_edge_type = any(keyword in lower_type for keyword in type_keywords)
        
        # 2. Network contains boundary-related keywords
        in_boundary_network = any(keyword in lower_network for keyword in network_keywords)
        
        return has_edge_type or in_boundary_network
    
    def potential_silent_device(self) -> bool:
        """
        Determine if this device is a silent device with minimal communication.
        
        Returns:
            True if device is a silent device, False otherwise
        """
        lower_type = self.device_type.lower()
        
        # Check for silent device indicators
        silent_keywords = ['silent', 'passive', 'sensor', 'legacy']
        has_silent_type = any(keyword in lower_type for keyword in silent_keywords)
        
        # Also consider devices with 'silent' attribute
        has_silent_attr = self.get_attribute('silent', False)
        
        return has_silent_type or has_silent_attr
    
    def is_vulnerable_to(self, vulnerability_type: str) -> bool:
        """
        Determine if the device is potentially vulnerable to a specific vulnerability type.
        
        Args:
            vulnerability_type: Type of vulnerability to check
            
        Returns:
            True if device is potentially vulnerable, False otherwise
        """
        lower_type = self.device_type.lower()
        vulnerability_type = vulnerability_type.lower()
        
        # Map vulnerability types to device types
        vulnerability_map = {
            'modbus': ['plc', 'controller', 'rtu'],
            'firmware': ['plc', 'controller', 'gateway', 'sensor', 'legacy'],
            'dos': ['scada', 'hmi', 'server'],
            'web': ['hmi', 'server', 'gateway', 'workstation'],
            'protocol': ['protocol', 'converter', 'gateway', 'edge'],
            'authentication': ['gateway', 'edge', 'firewall', 'router']
        }
        
        # Check if device type matches vulnerability
        if vulnerability_type in vulnerability_map:
            device_keywords = vulnerability_map[vulnerability_type]
            return any(keyword in lower_type for keyword in device_keywords)
        
        return False
    
    def __str__(self) -> str:
        """String representation of the device."""
        hidden_str = " (Hidden)" if self.hidden else ""
        edge_str = " (Edge)" if self.potential_edge_device() else ""
        silent_str = " (Silent)" if self.potential_silent_device() else ""
        
        return f"{self.ip} ({self.device_type}){hidden_str}{edge_str}{silent_str} - {self.network}"


def load_devices_from_ground_truth(ground_truth_file: str) -> List[Device]:
    """
    Load devices from ground truth file with correct attribute handling.
    
    Args:
        ground_truth_file: Path to the ground truth JSON file
        
    Returns:
        List of Device objects
    """
    import json
    import logging
    
    logger = logging.getLogger(__name__)
    logger.info(f"Loading devices from ground truth file: {ground_truth_file}")
    
    devices = []
    
    try:
        # Load the file
        with open(ground_truth_file, 'r') as f:
            device_data = json.load(f)
        
        # Track device counts by category
        category_counts = {'normal': 0, 'hidden': 0}
        
        # Process both normal and hidden devices
        for category in ['normal', 'hidden']:
            if category in device_data:
                for ip, details in device_data[category].items():
                    # Create device with correct attributes
                    device = Device(
                        ip=ip,
                        device_type=details.get('type', 'Unknown'),
                        network=details.get('network', 'Unknown'),
                        hidden=(category == 'hidden')
                    )
                    
                    # Add other attributes
                    for key, value in details.items():
                        if key not in ['type', 'network']:
                            device.add_attribute(key, value)
                    
                    # Add protocols if present
                    if 'protocols' in details:
                        for protocol in details['protocols']:
                            device.add_protocol(str(protocol))
                    
                    devices.append(device)
                    category_counts[category] += 1
        
        # Log summary of loaded devices
        logger.info(f"Loaded {len(devices)} total devices: "
                    f"{category_counts['normal']} normal, {category_counts['hidden']} hidden")
        
        return devices
    
    except FileNotFoundError:
        logger.error(f"Ground truth file not found: {ground_truth_file}")
        return []
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in ground truth file: {ground_truth_file}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error loading devices: {e}", exc_info=True)
        return []