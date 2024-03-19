import sqlite3
import logging
import os
from datetime import datetime, timedelta
from logger_config import setup_logging

session_logger, error_logger = setup_logging()

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

def setup_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(CREATE_HOSTS_TABLE)
    cur.execute(CREATE_NETSTAT_TABLE)  # Create the netstat_output table
    conn.commit()
    conn.close()

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

def get_recent_hosts(db_path, days=2):
    recent_threshold = datetime.now() - timedelta(days=days)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""SELECT ip_address FROM hosts
                       WHERE last_discovery >= ?""", (recent_threshold.isoformat(),))
        recent_hosts = {row[0] for row in cur.fetchall()}  # Use a set for efficient lookups
        return recent_hosts
    finally:
        conn.close()


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


def get_linux_hosts(db_path):
    """Fetches Linux hosts from the database.

    Args:
        db_path (str): Path to the SQLite database file.

    Returns:
        list: A list of tuples representing Linux hosts (id, ip_address).
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, ip_address FROM hosts WHERE host_class='linux'")
        linux_hosts = cur.fetchall()
        return linux_hosts
    finally:
        conn.close()
