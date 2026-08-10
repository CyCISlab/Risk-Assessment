"""
Industrial Control System Simulation Configuration

Defines network architectures, protocols, and vulnerability scenarios for ICS simulations.
Supports both standard and edge/hidden network topologies.
"""

from typing import Dict

SIMULATIONS: Dict[str, Dict] = {
    "standard_network": {
        "description": "Standard ICS network with typical components",
        "simulation_time": 300,
        "network": {
            "it_nodes": 1,
            "dmz_nodes": 1,
            "ot_control_nodes": 5,
            "ot_process_nodes": 4,
            "maintenance_nodes": 1
        },
        "protocols": {
            "modbus_port": 502,
            "dnp3_port": 20000,
            "bacnet_port": 47808,
            "proprietary_port": 8099,
            "maintenance_port": 22
        },
        "device_types": {
            "dmz": ["SCADA (DMZ)"],
            "control": ["HMI", "EWS", "PLC1", "PLC2", "PLC3"],
            "process": ["Legacy PLC", "Silent Sensor", "Serial Device", "Hidden Backup"],
            "maintenance": ["Maintenance Interface"]
        },
        "scenarios": [
            "SpiderControlHMIVulnerability",
            "ModbusTCPRCEVulnerability",
            "SCADADenialOfServiceVulnerability"
        ]
    },
    "edge_hidden_network": {
        "description": "Network with focus on edge and hidden devices",
        "simulation_time": 300,
        "network": {
            "it_nodes": 2,
            "dmz_nodes": 3,
            "ot_control_nodes": 4,
            "ot_process_nodes": 6,
            "maintenance_nodes": 2
        },
        "protocols": {
            "modbus_port": 502,
            "dnp3_port": 20000,
            "bacnet_port": 47808,
            "proprietary_port": 8099,
            "maintenance_port": 22,
            "edge_gateway_port": 9000,
            "firmware_update_port": 2323
        },
        "device_types": {
            "it": ["Corporate Firewall", "IT Management Server"],
            "dmz": ["DMZ Router", "Edge Gateway", "Protocol Converter"],
            "control": ["SCADA Server", "HMI Workstation", "Engineering Station", "Control PLC"],
            "process": ["Legacy PLC", "Hidden Sensor 1", "Hidden Sensor 2", "Serial Gateway", "Serial Device", "Backup System"],
            "maintenance": ["Maintenance Server", "Vendor Connection"]
        },
        "scenarios": [
            "EdgeGatewayBypassVulnerability",
            "FirmwareUpdateVulnerability",
            "ProprietaryProtocolVulnerability"
        ]
    }
}