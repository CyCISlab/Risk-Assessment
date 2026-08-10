# Industrial Control System Vulnerability Assessment Framework

## Development Environment
- WSL Ubuntu 24.04
- Python 3.12.3 - Python virtual environment (venv)
- NS3 3.43

## Project Overview
This project implements a vulnerability assessment framework for industrial control systems (ICS), with a specific focus on comparing vulnerability scoring methodologies (CVSS 4.0 vs. IVSS) in standard and hidden device networks. The framework simulates network traffic, detects hidden devices, and analyzes the impact of vulnerabilities in different network configurations.

## Dependencies
The main dependencies include:
- matplotlib 3.10.1
- networkx 3.4.2
- numpy 2.2.5
- pandas 2.2.3
- scapy 2.6.1
- seaborn 0.13.2

Full dependencies are listed in requirements.txt.

## Project Structure

├── main.py                         # Main entry point
├── scanning/                       # Network scanning functionality
│   ├── device.py                   # Device representation
│   └── network_scanner.py          # Network scanning logic
├── scenarios/                      # Vulnerability scenarios
│   ├── edge_gateway_vulnerability.py
│   ├── firmware_update_vulnerability.py
│   ├── modbus_vulnerability.py
│   ├── proprietary_vulnerability.py    # Vulnerability scoring implementations
│   ├── scada_dos_vulnerability.py
│   ├── scada_hmi_vulnerability.py
│   └── vulnerability_scenario.py       # Base vulnerability class
├── scoring/                        
│   ├── cvss_calculator.py          # CVSS 4.0 implementation
│   ├── device_modifiers.py         # Device-specific score modifiers
│   └── ivss_calculator.py          # IVSS implementation
├── simulation/                     # Network simulation modules
│   ├── application_manager.py      # Application layer management
│   ├── device_manager.py           # Device management
│   ├── hidden_simulation.py        # Hidden device simulation
│   ├── network_builder.py          # Network topology construction
│   ├── simulation_config.py        # Simulation configuration
│   └── standard_simulation.py      # Standard network simulation
└── utils/                          # Utility functions
├── comparator.py               # Score comparison utilities
├── network_comparison.py       # Network comparison logic
├── sensitivity_analyser.py     # Sensitivity analysis
├── performance_timer.py        # Performance timing utilities
├── topology.py                 # Network topology utilities
└── visualiser.py               # Visualization tools

## Setup Instructions
1. Install WSL Ubuntu 24.04 if on windows, or use native installation.
2. Install and build NS3 3.43:
    wget https://www.nsnam.org/releases/ns-allinone-3.43.tar.bz2
    tar -xjf ns-allinone-3.43.tar.bz2
    cd ns-allinone-3.43
    ./build.py
3. Set up Python environment:
    sudo apt update
    sudo apt install python3.12 python3.12-venv python3-pip
4. Create virtual environment
    python3.12 -m venv .venv
    source .venv/bin/activate
5. Install dependencies
    pip install -r requirements.txt

## Running the Framework

1. Activate the virtual environment:
- source .venv/bin/activate
2. Run the main script:
-  python main.py
3. For specific analyses:
-  python main.py --sensitivity-analysis
-  python main.py --network-comparison
4. For specific cababilities, use --help.
