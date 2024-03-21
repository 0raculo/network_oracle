import winrm
import re

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
        return False
    except winrm.exceptions.InvalidCredentialsError as e:
        # This indicates that the credentials were rejected, implying WinRM is active
        print(f"Invalid credentials error on {host}, indicating WinRM service is active.")
        return True
    except Exception as e:
        # Catch-all for any other exceptions
        print(f"WinRM connection to {host} failed with an unexpected error: {str(e)}")
        return False

def run_winrm_command(host, username, password, command):
    print(f"Attempting to connect to {host} with user {username} and {password}")
    session = winrm.Session(f'http://{host}:5985/wsman', auth=(username, password), transport='ntlm')
    result = session.run_ps(command)
    print(f"Command executed on {host}, checking for errors...")
    if result.std_err:
        print(f"Error executing command on {host}: {result.std_err.decode('utf-8')}")
    return result.std_out.decode('utf-8'), result.std_err.decode('utf-8')


def parse_windows_netstat_output(netstat_output):
    print("Parsing netstat output...")
    parsed_data = []
    for line in netstat_output.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 5 and parts[1] != 'Local':
            local_ip, local_port = parts[1].rsplit(':', 1)
            remote_ip, remote_port = parts[2].rsplit(':', 1)
            state = parts[3]
            pid = parts[4]

            parsed_data.append({
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'state': state,
                'pid': pid,
                'type': 'listening' if state == 'LISTENING' else 'established'
            })
    print(f"Finished parsing. Total connections parsed: {len(parsed_data)}")
    return parsed_data

def process_windows_hosts(ip_address, credentials_file='known_hosts_credentials.txt'):
    credentials = load_known_host_credentials(credentials_file)

    if ip_address in credentials:
        cred = credentials[ip_address]
        print(f"Processing host: {ip_address}")
        netstat_output, error = run_winrm_command(ip_address, cred['username'], cred['password'], 'netstat -ano')

        if error:
            print(f"Skipping host {ip_address} due to error.")
            return

        parsed_output = parse_windows_netstat_output(netstat_output)
        # Further processing...
        print(f"Processed {len(parsed_output)} connections for host {ip_address}")
        print(f"{parsed_output}")
    else:
        print(f"No credentials found for host {ip_address}.")

if __name__ == '__main__':
    process_windows_hosts('192.168.69.196')
