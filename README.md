# Network Dependencies Discovery Tool

## Overview

This tool automates the discovery of network dependencies between hosts within specified subnets. It leverages netstat output parsed from each host to identify and log connections, categorizing them as either incoming or outgoing. The tool supports Linux and BSD systems and requires SSH access to remote hosts.

## Requirements

- Python 3.x: Ensure Python 3 is installed on the system where the script will be executed.
- External Libraries: Required Python libraries are listed in requirements.txt. Install them using pip install -r requirements.txt.
- SSH Access: The script requires SSH access to remote hosts. Ensure SSH keys are set up or passwords are available.
- SQLite Database: The script uses an SQLite database to store discovered connections.


## Setup

1. Clone the Repository: Clone or download the script files to your local system.
2. Install Dependencies: Install the required Python libraries with pip install -r requirements.txt.
3. Configure SSH Access: Ensure SSH keys are configured for Linux hosts and passwords are available for Windows hosts.
4. Database Initialization: The script automatically sets up the SQLite database on the first run.


## Configuration

Create a config.yaml file in the same directory as the script with the following structure:


    database:
    path: "network_dependencies.db"

    network_scan:
    subnets:
        - "192.168.1.0/24"
        - "10.0.0.0/24"

    credentials:
    linux:
        ssh_key_path: "/path/to/ssh/key"
    windows:
        username: "admin"
        password: "password"


## SSH Keys and Password Files

- Linux Hosts: Store SSH private keys at the location specified in config.yaml.
- Windows Hosts: Provide a plaintext file with credentials formatted as ip_address:username:password per line.

## Usage

Run the script with Python, optionally specifying a subnet to scan:


`python initial.py [subnet]`

If no subnet is provided, the script scans the subnets listed in config.yaml.

## Mermaid Diagram Generation

After processing, the script generates a Mermaid diagram representing network connections, outputting to diagram_%date%.md. This diagram visualizes hosts, connections, and involved ports.