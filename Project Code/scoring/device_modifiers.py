"""
Device Modifiers Module

This module contains functions for calculating IVSS environmental modifiers
based on device characteristics discovered through network scanning.
These modifiers are used to enhance vulnerability scoring with
device-specific security characteristics.
"""

from scoring.ivss_calculator import IVSSCalculator

def calculate_device_modifiers(device, scanner_results=None):
    """
    Calculate IVSS environmental modifiers for a device.
    
    Args:
        device: Device object with device characteristics
        scanner_results: Optional scanner results for additional context
        
    Returns:
        Dictionary of IVSS modifiers appropriate for the device
    """
    modifiers = {}
    
    # Add process and system impact modifiers
    process_modifiers = calculate_process_impact_modifiers(device)
    system_modifiers = calculate_system_impact_modifiers(device)
    
    modifiers.update(process_modifiers)
    modifiers.update(system_modifiers)
    
    # Log debug information about the modifiers
    device_id = getattr(device, 'id', 'unknown')
    device_type = getattr(device, 'device_type', 'unknown')
    modifier_str = ', '.join([f"{key}={value:.2f}" for key, value in modifiers.items()])
    
    return modifiers

def calculate_asset_access_modifier(device):
    """
    Calculate Asset Access (LA) modifier value from scanner results.
    Returns the appropriate IVSS constant based on detection difficulty.
    """
    # Get detection status for all scanning methods
    active_detected = getattr(device, 'active_scan_status', '') == 'Detected'
    passive_detected = getattr(device, 'passive_monitoring_status', '') == 'Detected'
    specialised_detected = getattr(device, 'specialized_discovery_status', '').startswith('Detected')
    
    # Calculate detection score (0-1)
    if active_detected:
        # Easily detected with basic scanning - most accessible
        return IVSSCalculator.ASSET_ACCESS_ADJACENT_REMOTE  # 1.0
    elif passive_detected:
        # Detected with passive monitoring
        return IVSSCalculator.ASSET_ACCESS_LOCAL_NETWORK  # 0.5
    elif specialised_detected:
        # Only detected with specialised techniques
        return IVSSCalculator.ASSET_ACCESS_LOCAL_NETWORK  # 0.5
    else:
        # Not detected by any method - least accessible
        return IVSSCalculator.ASSET_ACCESS_LOCAL_HOST  # 0.25

def calculate_network_segmentation_modifier(device):
    """
    Calculate Network Segmentation (CP) modifier from network location.
    Returns the appropriate IVSS constant based on network type.
    """
    network = getattr(device, 'network', '').upper()
    
    if 'PROCESS' in network or 'FIELD' in network:
        # Deep OT network - least segmented from industrial systems
        return IVSSCalculator.NETWORK_SEGMENTATION_NONE  # 1.0
    elif 'DMZ' in network:
        # DMZ network - partial segmentation
        return IVSSCalculator.NETWORK_SEGMENTATION_DMZ_ONLY  # 0.85
    elif 'CONTROL' in network:
        # Control network - more segmentation than process, less than IT
        return IVSSCalculator.NETWORK_SEGMENTATION_PARTIAL  # 0.75
    else:
        # IT or enterprise network - most segmented from industrial systems
        return IVSSCalculator.NETWORK_SEGMENTATION_COMPLIANT  # 0.2

def calculate_process_impact_modifiers(device):
    """
    Calculate Process Impact modifiers (VI, MI, CI) based on device type and role.
    Returns a dictionary with the appropriate IVSS constants.
    """
    device_type = getattr(device, 'device_type', '').lower()
    is_hidden = getattr(device, 'hidden', False)
    
    # Set defaults
    modifiers = {
        'vi': IVSSCalculator.PROCESS_VISIBILITY_NONE,    # 0.0
        'mi': IVSSCalculator.PROCESS_MONITORING_NONE,    # 0.0
        'ci': IVSSCalculator.PROCESS_CONTROL_NONE        # 0.0
    }
    
    # Visibility Impact (VI)
    if 'hmi' in device_type or 'scada' in device_type:
        modifiers['vi'] = IVSSCalculator.PROCESS_VISIBILITY_COMPLETE  # 1.0
    elif 'monitor' in device_type or 'sensor' in device_type:
        modifiers['vi'] = IVSSCalculator.PROCESS_VISIBILITY_PARTIAL  # 0.5
    elif is_hidden:
        # Hidden devices may affect visibility indirectly
        modifiers['vi'] = IVSSCalculator.PROCESS_VISIBILITY_PARTIAL  # 0.5
    
    # Monitoring Impact (MI)
    if 'scada' in device_type or 'historian' in device_type:
        modifiers['mi'] = IVSSCalculator.PROCESS_MONITORING_COMPLETE  # 1.0
    elif 'sensor' in device_type or 'monitor' in device_type:
        modifiers['mi'] = IVSSCalculator.PROCESS_MONITORING_PARTIAL  # 0.5
    
    # Control Impact (CI)
    if 'plc' in device_type or 'controller' in device_type or 'rtu' in device_type:
        modifiers['ci'] = IVSSCalculator.PROCESS_CONTROL_COMPLETE  # 1.0
    elif 'gateway' in device_type or 'edge' in device_type:
        modifiers['ci'] = IVSSCalculator.PROCESS_CONTROL_PARTIAL  # 0.5
    
    return modifiers

def calculate_system_impact_modifiers(device):
    """
    Calculate System Impact modifiers (PI, RI, SI) based on device characteristics.
    Returns a dictionary with the appropriate IVSS constants.
    """
    device_type = getattr(device, 'device_type', '').lower()
    is_hidden = getattr(device, 'hidden', False)
    network = getattr(device, 'network', '').lower()
    
    # Set defaults
    modifiers = {
        'pi': IVSSCalculator.SYSTEM_PRODUCTION_IMPACT_LOW,     # 0.4
        'ri': IVSSCalculator.SYSTEM_RELIABILITY_IMPACT_LOW,    # 0.33
        'si': IVSSCalculator.SYSTEM_SAFETY_IMPACT_LOW          # 0.5
    }
    
    # Production Impact (PI)
    if 'plc' in device_type or 'controller' in device_type:
        # Direct control over production processes
        modifiers['pi'] = IVSSCalculator.SYSTEM_PRODUCTION_IMPACT_HIGH  # 1.0
    elif 'scada' in device_type or 'hmi' in device_type:
        # Indirect control or monitoring of production
        modifiers['pi'] = IVSSCalculator.SYSTEM_PRODUCTION_IMPACT_MEDIUM  # 0.7
    
    # Reliability Impact (RI)
    if 'gateway' in device_type or 'router' in device_type:
        # Network infrastructure affecting reliability
        modifiers['ri'] = IVSSCalculator.SYSTEM_RELIABILITY_IMPACT_HIGH  # 1.0
    elif is_hidden or 'edge' in device_type:
        # Hidden devices or edge devices may affect reliability
        modifiers['ri'] = IVSSCalculator.SYSTEM_RELIABILITY_IMPACT_MEDIUM  # 0.66
    
    # Safety Impact (SI)
    if 'safety' in device_type or 'emergency' in device_type:
        # Direct safety systems
        modifiers['si'] = IVSSCalculator.SYSTEM_SAFETY_IMPACT_HIGH  # 1.0
    elif 'plc' in device_type and 'process' in network:
        # Process control PLCs may have safety implications
        modifiers['si'] = IVSSCalculator.SYSTEM_SAFETY_IMPACT_MEDIUM  # 0.8
    
    return modifiers