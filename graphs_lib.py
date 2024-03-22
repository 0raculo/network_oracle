# graphs_lib.py
from datetime import datetime

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
        file.write(mermaid_code)
    print(f"Mermaid diagram code written to {filename}")
