import winrm
import re
import db_manager
from logger_config import setup_logging

session_logger, error_logger, debug_logger = setup_logging()

def load_known_host_credentials(filename):
    credentials = {}
    with open(filename, 'r') as file:
        for line in file:
            host, username, password = line.strip().split(':')
            credentials[host] = {'username': username, 'password': password}
    return credentials

def attempt_winrm_connection(host):
    # Use a non-existent username and password to trigger an authentication failure
    fake_credentials = {'username': 'fakeuser', 'password': 'fakepassword'}

    try:
        session = winrm.Session(f'http://{host}:5985/wsman', auth=(fake_credentials['username'], fake_credentials['password']), transport='ntlm')
        # Run a simple command that would succeed if authenticated
        result = session.run_ps('echo test')

        # Analyze the response
        if result.status_code == 0:
            # This case is unlikely with fake credentials but indicates WinRM is active
            return True
        else:
            # If we receive a specific error related to authentication, WinRM is active but we used wrong credentials
            print(f"Authentication failure with WinRM on {host}, indicating WinRM service is active.")
            return True
    except winrm.exceptions.WinRMTransportError as e:
        # This likely indicates a network-level error such as a timeout or closed port
        print(f"WinRM transport error on {host}: {str(e)}")
        debug_logger.debug(f"WinRM transport error on {host}: {str(e)}")
        return False
    except winrm.exceptions.InvalidCredentialsError as e:
        # This indicates that the credentials were rejected, implying WinRM is active
        print(f"Invalid credentials error on {host}, indicating WinRM service is active.")
        debug_logger.debug(f"Invalid credentials error on {host}, indicating WinRM service is active.")
        return True
    except Exception as e:
        # Catch-all for any other exceptions
        print(f"WinRM connection to {host} failed.")
        debug_logger.debug(f"WinRM connection to {host} failed.")
        return False

def run_winrm_command(host, username, password, command):
    print(f"Attempting to connect to {host} with user {username} and {password}")
    debug_logger.debug(f"Attempting to connect to {host} with user {username} and {password}")
    session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='ntlm')
    result = session.run_ps(command)
    if result.std_err:
        print(f"Error executing command on {host}: {result.std_err.decode('utf-8')}")
        debug_logger.debug(f"Error executing command on {host}: {result.std_err.decode('utf-8')}")
    return result.std_out.decode('utf-8'), result.std_err.decode('utf-8')

def parse_windows_netstat_output(netstat_output):
    print("Parsing netstat output...")
    debug_logger.debug("Parsing netstat output...")
    parsed_data = []  # To store parsed netstat entries
    listening_ports = set()  # To keep track of listening ports

    # First pass to identify listening ports
    for line in netstat_output.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 4 and parts[3] == 'LISTENING':
            _, port = parts[1].rsplit(':', 1)  # Assuming format [IP:PORT]
            listening_ports.add(port)

    # Second pass to parse connections
    for line in netstat_output.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 5 or parts[1] == 'Local' or parts[3] == 'LISTENING':
            continue  # Skip header, listening, and irrelevant lines

        local_ip, local_port = parts[1].rsplit(':', 1)
        remote_ip, remote_port = parts[2].rsplit(':', 1) if ':' in parts[2] else (parts[2], '*')
        state = parts[3]

        # Filter out entries without a remote IP and port
        if remote_ip == '0.0.0.0' or remote_ip == '*' or remote_ip == '[::]':
            continue

        # Determine connection type based on listening ports
        connection_type = 'incoming' if local_port in listening_ports else 'outgoing'

        parsed_data.append((remote_ip, remote_port, connection_type, local_port))

    print(f"Finished parsing. Total connections parsed: {len(parsed_data)}")
    debug_logger.debug(f"Finished parsing. Total connections parsed: {(parsed_data)}")
    return parsed_data

def process_windows_hosts(config, credentials):
    # Fetch Windows hosts from the database
    windows_hosts = db_manager.get_all_os_hosts(config['database']['path'], "windows")

    print(f"Found {len(windows_hosts)} Windows hosts in the database. Processing...")
    debug_logger.debug(f"Found {len(windows_hosts)} Windows hosts in the database. Processing...")
    all_netstat_outputs = []  # To collect netstat outputs for all hosts

    for host_id, ip_address in windows_hosts:
        # Check if the current host's credentials are available
        if ip_address in credentials:
            cred = credentials[ip_address]
            # Attempt to connect and run the command using WinRM
            netstat_output, error = run_winrm_command(ip_address, cred['username'], cred['password'], 'netstat -ano')
            debug_logger.debug("debug netstat_output output: " + netstat_output)
            if error:
                print(f"Skipping host {ip_address} due to error.")
                continue  # Skip to the next host if there's an error

            # Parse the netstat output
            parsed_output = parse_windows_netstat_output(netstat_output)
            debug_logger.debug("debug parsed output: " + str(parsed_output))
            db_manager.update_netstat_output(host_id, parsed_output)
            # Store the parsed data for the current host
            all_netstat_outputs.append(parsed_output)

            print(f"Processed {len(parsed_output)} connections for host {ip_address}")
        else:
            print(f"No credentials found for Windows host {ip_address}, skipping.")

    return all_netstat_outputs  # Return the collected outputs after processing all hosts

if __name__ == '__main__':
    process_windows_hosts('192.168.69.196')
