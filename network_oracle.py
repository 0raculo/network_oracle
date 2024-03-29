import sys
import logging
import nmap
import yaml
import argparse
import socket

### helper files import
import db_manager
import processor_linux
import processor_windows
import graphs_lib
from logger_config import setup_logging

session_logger, error_logger, debug_logger = setup_logging()

def load_config(config_path='config.yaml'):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def load_known_host_credentials(credentials_path='known_hosts_credentials.txt'):
    credentials = {}
    with open(credentials_path, 'r') as file:
        for line in file:
            ip_address, username, password = line.strip().split(':')
            credentials[ip_address] = {'username': username, 'password': password}
    return credentials

def scan_for_open_ports(subnet, nmap_arguments):
    nm = nmap.PortScanner()
    open_hosts = []

    nm.scan(hosts=subnet, arguments=nmap_arguments)

    for host in nm.all_hosts():
        # Check if the host has open ports specified in the scan arguments
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                port_info = nm[host][proto][port]
                # Check if the port is open and add the host to the list
                if port_info['state'] == 'open':
                    open_hosts.append(host)
                    break  # Exit the loop after finding the first open port for the host
    
    print(f"Debug - Total open hosts found: {len(open_hosts)}")

    return open_hosts

def scan_subnet(subnet, scan_arguments, excluded_hosts=None):
    print(f"Starting nmap scan on subnet: {subnet} with arguments: {scan_arguments}")
    open_hosts = scan_for_open_ports(subnet, scan_arguments)
    host_details = []

    if excluded_hosts is None:
        excluded_hosts = set()

    for host in open_hosts:
        if host in excluded_hosts:
            print(f"Skipping excluded host: {host}")
            continue  # Skip this host and move on to the next one

        print(f"Processing host: {host}")
        os_type = 'unknown'
        host_class = 'other'  # Default classification

        # Attempt to detect SSH banner or WinRM connection to check if Windows or Linux Host
        # Then, we can update db accordingly
        try:
            print(f"Attempting to detect SSH banner on {host}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((host, 22))
                banner = sock.recv(1024).decode('utf-8', 'ignore')
                if 'SSH' in banner:
                    print(f"SSH banner detected on {host}")
                    host_class = 'linux'  # SSH banner present, classify as Linux
                else:
                    print(f"No SSH banner detected on {host}.")
        except Exception as e:
            print(f"Failed to detect SSH banner on {host}: {e}. Let's see if it's a windows host using winrm!")
            if processor_windows.attempt_winrm_connection(host):
                        print(f"WinRM detected on {host}")
                        host_class = 'windows'  # WinRM connection successful, classify as Windows
                        # If not might be an iot device. Keep it as other.
        host_details.append((host, os_type, host_class))

    return host_details

def cleanup():
    # Delete duplicate connections from the database
    print("Deleting duplicate connections...")
    db_manager.delete_duplicate_connections()
    print("Duplicate connections deleted.")

    # Generate Mermaid diagram code based on the connections
    # and output the Mermaid code to a Markdown file
    connections = db_manager.fetch_connections()
    mermaid_code = graphs_lib.generate_mermaid_code(connections)
    graphs_lib.output_to_markdown(mermaid_code)
    print("Mermaid diagram generation complete.")


def main(subnet=None):
    parser = argparse.ArgumentParser(description='Network Oracle v.1.0')
    parser.add_argument('--subnet', help='Subnet to scan and update in the database', type=str)
    parser.add_argument('--exclude', nargs='+', help='List of hosts to exclude from the scan', default=[], dest='exclude')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    config = load_config()
    global DB_PATH
    DB_PATH = config['database']['path']
    db_manager.setup_database()

    excluded_hosts = set(args.exclude)  # Initialize with values from --exclude
    recent_host_ips = db_manager.get_recent_hosts(DB_PATH)  # Fetch recently scanned hosts

    # Combine both sets to have a single set of hosts to exclude from scanning
    excluded_hosts.update(recent_host_ips)

    if args.verbose:
        session_logger.setLevel(logging.DEBUG)

    # Determine which subnet(s) to scan
    if args.subnet:
        subnets_to_scan = [args.subnet]
    else:
        subnets_to_scan = config['network_scan']['subnets']
        print("No specific subnet provided. Using subnets from the configuration file.")

    # Scan the determined subnet(s), skipping both manually excluded and recently scanned hosts
    for subnet in subnets_to_scan:
        print(f"Scanning subnet: {subnet}")
        discovered_hosts_info = scan_subnet(subnet, config.get('nmap', {}).get('scan_arguments', "-O --top-ports 100"), excluded_hosts=excluded_hosts)
        db_manager.populate_hosts(discovered_hosts_info)

    # Process linux hosts  with the loaded config and credentials
    print("Processing linux hosts...")
    config = load_config()  # Your function to load the configuration
    credentials = load_known_host_credentials(config['credentials']['known_hosts_file'])  # Your function to load credentials
    all_netstat_outputs = processor_linux.ssh_and_run(config, credentials)
    print("Processing linux hosts complete. Processing Windows hosts") 
    processor_windows.process_windows_hosts(config, credentials)
    print("Processing windows hosts...")

    #Remove duplicates from DB and generate mermaid code
    cleanup()

if __name__ == '__main__':
    subnet_arg = sys.argv[1] if len(sys.argv) == 2 else None
    main(subnet_arg)
