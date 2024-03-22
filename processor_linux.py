import paramiko
import socket
import db_manager
from logger_config import setup_logging

session_logger, error_logger, debug_logger = setup_logging()


def ssh_and_run(config, credentials):
    linux_hosts = db_manager.get_all_os_hosts(config['database']['path'], "linux")

    print(f"Found {len(linux_hosts)} linux hosts in the database. Processing...")

    all_netstat_outputs = []  # Collect netstat outputs for all hosts

    for host_id, ip_address in linux_hosts:
        if not is_port_open(ip_address):
            session_logger.info(f"Port 22 is closed on {ip_address}. Bypassing this host.")
            continue  # Skip to the next host

        # Use the provided credentials and config to establish an SSH connection
        ssh_key_success = False
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for username in config['credentials']['ssh_usernames']:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(config['credentials']['ssh_private_key'])
                ssh.connect(ip_address, username=username, pkey=pkey, allow_agent=False,look_for_keys=False)
                session_logger.info(f"SSH key login successful for: {ip_address} with username: {username}")
                ssh_key_success = True
                break  # Exit the username loop on successful connection
            except paramiko.ssh_exception.AuthenticationException:
                print(f"SSH key login failed for: {ip_address} with username: {username}")
                session_logger.error(f"SSH key login failed for: {ip_address} with username: {username}")

        if not ssh_key_success and ip_address in credentials:
            cred = credentials[ip_address]
            # Attempt password login if SSH key authentication fails
            try:
                ssh.connect(ip_address, username=cred['username'], password=cred['password'])
                session_logger.info(f"Password login successful for: {ip_address} with username: {cred['username']}")
                ssh_key_success = True
            except paramiko.ssh_exception.AuthenticationException:
                print(f"Password login failed for: {ip_address} with username: {cred['username']}")
                session_logger.error(f"Password login failed for: {ip_address} with username: {cred['username']}")

        if ssh_key_success:
            # SSH operations like ssh_run_netstat
            stdin, stdout, stderr = ssh.exec_command('netstat -tunap')
            command_output = stdout.read().decode('utf-8')
            parsed_output = parse_linux_netstat_output(command_output)
            db_manager.update_netstat_output(host_id, parsed_output)
            all_netstat_outputs.append(parsed_output)  # Append the output for this host

        ssh.close()

    return all_netstat_outputs  # Return the collected outputs after processing all hosts


def parse_linux_netstat_output(netstat_output):
    listening_ports = []  # To store ports on which the machine is listening
    parsed_data = []  # To store parsed netstat entries
    debug_logger.debug(netstat_output)
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
