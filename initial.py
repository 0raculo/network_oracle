import os
import sys
import re
import sqlite3
import nmap
from datetime import datetime, timedelta
import paramiko
import yaml
import logging
from datetime import datetime
import argparse
import socket

# Setup command-line argument parsing

# Create a log directory if it doesn't exist
log_dir = 'log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Updated logging setup
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
session_logger = logging.getLogger("session")
session_handler = logging.FileHandler(f"{log_dir}/session_{timestamp}.log")
session_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
session_handler.setFormatter(session_formatter)
session_logger.addHandler(session_handler)
session_logger.setLevel(logging.INFO)

error_logger = logging.getLogger("error")
error_handler = logging.FileHandler(f"{log_dir}/error_{timestamp}.log")
error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - ERROR - %(message)s')
error_handler.setFormatter(error_formatter)
error_logger.addHandler(error_handler)
error_logger.setLevel(logging.ERROR)


DB_PATH = 'network_dependencies.db'  # Path to your SQLite database

CREATE_HOSTS_TABLE = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    host_type TEXT,
    host_class TEXT,
    last_discovery TIMESTAMP
);
"""

CREATE_NETSTAT_TABLE = """
CREATE TABLE IF NOT EXISTS netstat_output (
    id INTEGER PRIMARY KEY,
    host_id INTEGER,
    remote_host TEXT,
    remote_port INTEGER,
    connection_type TEXT,
    local_port INTEGER,
    FOREIGN KEY (host_id) REFERENCES hosts(id),
    UNIQUE(host_id, remote_host, remote_port)  -- Ensure this UNIQUE constraint is defined
);


"""




def load_config(config_path='config.yaml'):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config


def setup_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(CREATE_HOSTS_TABLE)
    cur.execute(CREATE_NETSTAT_TABLE)  # Create the netstat_output table
    conn.commit()
    conn.close()


def scan_subnet(subnet, scan_arguments="-sn", excluded_hosts=None):
    scanner = nmap.PortScanner()
    print(f"Starting nmap scan on subnet: {subnet} with arguments: {scan_arguments}")
    scanner.scan(hosts=subnet, arguments=scan_arguments)
    host_details = []

    if excluded_hosts is None:
        excluded_hosts = set()

    for host in scanner.all_hosts():
        if host in excluded_hosts:
            print(f"Skipping excluded host: {host}")
            continue  # Skip this host and move on to the next one

        print(f"Processing host: {host}")
        os_type = 'unknown'
        host_class = 'other'  # Default classification

        # Attempt to detect SSH banner
        try:
            print(f"Attempting to detect SSH banner on {host}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((host, 22))
                banner = sock.recv(1024).decode('utf-8', 'ignore')
                if 'SSH' in banner:
                    print(f"SSH banner detected on {host}")
                    host_class = 'linux'  # SSH banner present, classify as Linux
                else:
                    print(f"No SSH banner detected on {host}")
        except Exception as e:
            print(f"Failed to detect SSH banner on {host}: {e}")

        host_details.append((host, os_type, host_class))

    return host_details


# Note: Make sure to replace 'default_username' and 'default_password' with actual default SSH credentials or handle them according to your security policies.




def populate_hosts(hosts):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    processed_hosts = []

    for ip_address, os_type, host_class in hosts:
        try:
            last_discovery = datetime.now().isoformat()
            cur.execute("""INSERT INTO hosts (ip_address, host_type, host_class, last_discovery)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(ip_address)
                           DO UPDATE SET host_type = excluded.host_type,
                                         host_class = excluded.host_class,
                                         last_discovery = excluded.last_discovery;""",
                        (ip_address, os_type, host_class, last_discovery))
            processed_hosts.append(ip_address)
            session_logger.info(f"Processed host: {ip_address}")
        except Exception as e:
            error_logger.error(f"Failed to process host {ip_address}: {e}")

    conn.commit()
    conn.close()
    return processed_hosts



def get_recent_hosts(days=2):
    recent_threshold = datetime.now() - timedelta(days=days)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""SELECT ip_address, host_type, host_class FROM hosts
                   WHERE last_discovery >= ?""", (recent_threshold.isoformat(),))
    recent_hosts = cur.fetchall()

    conn.close()
    return recent_hosts


def get_host_last_discovery(ip_address):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT last_discovery FROM hosts WHERE ip_address = ?", (ip_address,))
    row = cur.fetchone()
    conn.close()
    
    if row:
        # Parse ISO 8601 string back into a datetime object
        last_discovery = datetime.fromisoformat(row[0])
        return last_discovery
    return None


def load_known_host_credentials(credentials_path='known_hosts_credentials.txt'):
    credentials = {}
    with open(credentials_path, 'r') as file:
        for line in file:
            ip_address, username, password = line.strip().split(':')
            credentials[ip_address] = {'username': username, 'password': password}
    return credentials




def parse_netstat_output(netstat_output):
    listening_ports = []  # To store ports on which the machine is listening
    parsed_data = []  # To store parsed netstat entries

    # First pass to find listening ports
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) < 6 or 'LISTEN' not in parts:
            continue  # Skip irrelevant lines

        # Extract and store listening ports
        if ':' in parts[3]:  # Ensure the Local Address contains ':'
            _, local_port = parts[3].rsplit(':', 1)
            listening_ports.append(local_port)

    # Second pass to parse connections
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[5] in ['LISTEN', 'TIME_WAIT']:
            continue  # Skip lines that are not established connections

        # Handle Local Address
        if ':' in parts[3]:  # Check for ':' to safely unpack
            local_ip, local_port = parts[3].rsplit(':', 1)
        else:
            continue  # Skip this line if ':' is missing in the Local Address

        # Handle Foreign Address
        if ':' in parts[4]:
            remote_ip, remote_port = parts[4].rsplit(':', 1)
        else:
            remote_ip = parts[4]  # Assume the whole part is the IP if ':' is missing
            remote_port = ''  # Set a default or placeholder value for remote_port

        # Ignore connections to/from loopback address
        if local_ip == '127.0.0.1' or remote_ip == '127.0.0.1':
            continue

        # Determine connection type based on listening ports
        connection_type = 'incoming' if local_port in listening_ports else 'outgoing'

        parsed_data.append((remote_ip, remote_port, connection_type, local_port))

    return parsed_data




def extract_open_ports(netstat_output):
    open_ports = set()
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) < 6 or 'LISTEN' not in parts[5]:
            continue  # Focus on lines indicating listening ports

        local_ip, local_port = parts[3].rsplit(':', 1)
        if local_ip in ['0.0.0.0', '::']:  # Listening on all interfaces (IPv4 and IPv6)
            open_ports.add(local_port)

    return open_ports



def update_netstat_output(host_id, netstat_data):
    if netstat_data is None:
        netstat_data = []  # Initialize to an empty list if None
        print("netstat_data is None")  # Or use logging

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for remote_ip, remote_port, connection_type, local_port in netstat_data:
        # Use ON CONFLICT DO NOTHING to ignore attempts to insert duplicates
        cur.execute("""INSERT INTO netstat_output (host_id, remote_host, remote_port, connection_type, local_port)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(host_id, remote_host, remote_port) DO NOTHING""",
                    (host_id, remote_ip, remote_port, connection_type, local_port))
    conn.commit()
    conn.close()


def is_port_open(ip_address, port=22, timeout=3):
    """
    Check if a specific port is open on a host.

    Parameters:
    - ip_address: The IP address of the host to check.
    - port: The port number to check. Default is 22 (SSH).
    - timeout: Timeout in seconds for the connection attempt. Default is 3 seconds.

    Returns:
    - True if the port is open, False otherwise.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip_address, port))
    sock.close()
    return result == 0  # Returns True if the port is open (connect_ex returns 0 for success)


def process_linux_hosts():
    config = load_config()  # Load the configuration
    credentials = load_known_host_credentials(config['credentials']['known_hosts_file'])
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT id, ip_address FROM hosts WHERE host_class='linux'")
    linux_hosts = cur.fetchall()

    print(f"Found {len(linux_hosts)} linux hosts in the database. Processing...")

    all_netstat_outputs = []  # Collect netstat outputs for all hosts

    for host_id, ip_address in linux_hosts:
        if not is_port_open(ip_address):
            print(f"Port 22 is closed on {ip_address}. Bypassing this host.")
            continue  # Skip to the next host

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_key_success = False

        for username in config['credentials']['ssh_usernames']:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(config['credentials']['ssh_private_key'])
                ssh.connect(ip_address, username=username, pkey=pkey)
                print(f"SSH key login successful for: {ip_address} with username: {username}")
                ssh_key_success = True
                break  # Exit the username loop on successful connection
            except paramiko.ssh_exception.AuthenticationException:
                print(f"SSH key login failed for: {ip_address} with username: {username}")

        if not ssh_key_success and ip_address in credentials:
            cred = credentials[ip_address]
            # Attempt password login if SSH key authentication fails
            for username, password in credentials.items():
                try:
                    ssh.connect(ip_address, username=cred['username'], password=cred['password'])
                    print(f"Password login successful for: {ip_address} with username: {cred['username']}")
                    ssh_key_success = True
                    break  # Exit the credentials loop on successful connection
                except paramiko.ssh_exception.AuthenticationException:
                    print(f"Password login failed for: {ip_address} with username: {cred['username']}")

        if ssh_key_success:
            # SSH operations like ssh_run_netstat
            stdin, stdout, stderr = ssh.exec_command('netstat -tunap')
            command_output = stdout.read().decode('utf-8')
            netstat_output = parse_netstat_output(command_output)
            update_netstat_output(host_id, netstat_output)
            all_netstat_outputs.append(netstat_output)  # Append the output for this host

        ssh.close()

    conn.close()
    return all_netstat_outputs  # Return the collected outputs after processing all hosts




def ssh_run_command(host_ip, username, password, command="hostname"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(host_ip, username=username, password=password)
        print(f"Connected to {host_ip}. Executing command...")  # Added console output
        stdin, stdout, stderr = ssh.exec_command(command)
        command_output = stdout.read().decode('utf-8').strip()
        command_error = stderr.read().decode('utf-8')

        session_logger.info(f"Hostname for {host_ip}: {command_output}")
        if command_error:
            error_logger.error(f"Error when getting hostname for {host_ip}: {command_error}")

    except paramiko.AuthenticationException:
        error_logger.error(f"Authentication failed for host {host_ip}.", exc_info=True)
        print(f"Authentication failed for host {host_ip}.")  # Added console output

    except Exception as e:
        error_logger.error(f"SSH connection or command execution failed for host {host_ip}: {e}", exc_info=True)
        print(f"SSH connection or command execution failed for host {host_ip}.")  # Added console output

    finally:
        ssh.close()
        print(f"SSH session closed for {host_ip}.")  # Added console output


def delete_duplicate_connections():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Select and log incoming connections to be deleted
    cur.execute("""SELECT id, host_id, remote_host, local_port, remote_port, connection_type FROM netstat_output
                   WHERE (id NOT IN (
                       SELECT MIN(id)
                       FROM netstat_output
                       WHERE connection_type = 'incoming'
                       GROUP BY host_id, remote_host, local_port
                   ) OR remote_port = '*') AND connection_type = 'incoming'""")
    for row in cur.fetchall():
        print(f"Deleting incoming duplicate or invalid connection: HostID={row[1]}, RemoteHost={row[2]}, LocalPort={row[3]}, RemotePort={row[4]}, Type={row[5]}")

    # Actual deletion for incoming duplicates or invalid entries
    cur.execute("""DELETE FROM netstat_output
                   WHERE (id NOT IN (
                       SELECT MIN(id)
                       FROM netstat_output
                       WHERE connection_type = 'incoming'
                       GROUP BY host_id, remote_host, local_port
                   ) OR remote_port = '*') AND connection_type = 'incoming'""")

    # Select and log outgoing connections to be deleted
    cur.execute("""SELECT id, host_id, remote_host, local_port, remote_port, connection_type FROM netstat_output
                   WHERE (id NOT IN (
                       SELECT MIN(id)
                       FROM netstat_output
                       WHERE connection_type = 'outgoing'
                       GROUP BY host_id, remote_host, remote_port
                   ) OR remote_port = '*') AND connection_type = 'outgoing'""")
    for row in cur.fetchall():
        print(f"Deleting outgoing duplicate or invalid connection: HostID={row[1]}, RemoteHost={row[2]}, LocalPort={row[3]}, RemotePort={row[4]}, Type={row[5]}")

    # Actual deletion for outgoing duplicates or invalid entries
    cur.execute("""DELETE FROM netstat_output
                   WHERE (id NOT IN (
                       SELECT MIN(id)
                       FROM netstat_output
                       WHERE connection_type = 'outgoing'
                       GROUP BY host_id, remote_host, remote_port
                   ) OR remote_port = '*') AND connection_type = 'outgoing'""")

    conn.commit()
    conn.close()


def fetch_connections():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""SELECT n.host_id, h.ip_address AS host_ip, n.remote_host, n.local_port, n.remote_port, n.connection_type
                   FROM netstat_output n
                   JOIN hosts h ON n.host_id = h.id""")
    connections = cur.fetchall()
    conn.close()
    return connections



def generate_mermaid_code(connections):
    mermaid_code = "graph LR\n"
    for _, host_ip, remote_host, local_port, remote_port, connection_type in connections:
        if connection_type == 'incoming':
            # Arrow points to the host for incoming connections
            connection_line = f"{remote_host} --\"Port {local_port}\"--> {host_ip}"
        else:  # 'outgoing'
            # Arrow points from the host for outgoing connections
            connection_line = f"{host_ip} --\"Port {remote_port}\"--> {remote_host}"

        mermaid_code += f"    {connection_line}\n"

    return mermaid_code




def output_to_markdown(mermaid_code):
    date_str = datetime.now().strftime("%Y%m%d")
    filename = f"diagram_{date_str}.md"
    with open(filename, 'w') as file:
        file.write("```mermaid\n")
        file.write(mermaid_code)
        file.write("```\n")
    print(f"Mermaid diagram code written to {filename}")




def main(subnet=None):
    parser = argparse.ArgumentParser(description='Network Oracle')
    parser.add_argument('--subnet', help='Subnet to scan and update in the database', type=str)
    parser.add_argument('--exclude', nargs='+', help='List of hosts to exclude from the scan', default=[], dest='exclude')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    config = load_config()
    global DB_PATH
    DB_PATH = config['database']['path']
    setup_database()

    excluded_hosts = set(args.exclude)  # Initialize excluded_hosts with values from --exclude

    if args.verbose:
        session_logger.setLevel(logging.DEBUG)

    # Determine which subnet(s) to scan
    if args.subnet:
        # Only scan the provided subnet
        subnets_to_scan = [args.subnet]
    else:
        # Fall back to subnets from the configuration file
        subnets_to_scan = config['network_scan']['subnets']
        print("No specific subnet provided. Using subnets from the configuration file.")

    # Scan the determined subnet(s)
    for subnet in subnets_to_scan:
        print(f"Scanning subnet: {subnet}")
        discovered_hosts_info = scan_subnet(subnet, config.get('nmap', {}).get('scan_arguments', "-O --top-ports 100"), excluded_hosts=excluded_hosts)
        populate_hosts(discovered_hosts_info)

    # Fetch recent hosts to avoid rescanning, if no specific subnet is provided
    if not subnet:
        recent_hosts = get_recent_hosts()
        if recent_hosts:
            print(f"Using {len(recent_hosts)} recently discovered hosts from the database.")
            for host in recent_hosts:
                print(f"Recently discovered host: {host[1]}")
        else:
            print("No recent hosts found in the database. Proceeding with subnet scanning.")
    else:
        recent_hosts = []

    # Process linux hosts
    print("Processing linux hosts...")
    process_linux_hosts()
    print("Processing complete.") 

    # Delete duplicate connections from the database
    print("Deleting duplicate connections...")
    delete_duplicate_connections()
    print("Duplicate connections deleted.")


    # Generate Mermaid diagram code based on the connections
    connections = fetch_connections()
    mermaid_code = generate_mermaid_code(connections)

    # Output the Mermaid code to a Markdown file
    output_to_markdown(mermaid_code)
    print("Mermaid diagram generation complete.")


if __name__ == '__main__':
    subnet_arg = sys.argv[1] if len(sys.argv) == 2 else None
    main(subnet_arg)



