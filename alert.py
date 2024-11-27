import sqlite3
import configparser
from datetime import datetime
import click

"""
Logic kiem tra alert:
- dau tien kiem tra trong valid_hosts trong register.ini, neu trung het thi No Alert
- neu con host-port la. thi kiem tra tiep trong db --> trung het thi No new alert
- neu khong co trong db -->In ra Alert 
"""

def init_db(db_path="open_ports.db"):
    """
    Initialize the database and create the table if it does not exist.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS open_ports (
            domain TEXT,
            port TEXT,
            scan_date INTEGER,
            alert_message TEXT,
            PRIMARY KEY (domain, port)
        )
    ''')
    conn.commit()
    return conn

def save_to_db(domain, port, alert_message, conn):
    """
    Save a new alert to the database or update an existing record.
    """
    cursor = conn.cursor()
    scan_date = int(datetime.now().timestamp())
    cursor.execute("""
        INSERT INTO open_ports (domain, port, scan_date, alert_message) 
        VALUES (?, ?, ?, ?) 
        ON CONFLICT(domain, port) DO UPDATE 
        SET scan_date=excluded.scan_date, alert_message=excluded.alert_message
    """, (domain, port, scan_date, alert_message))
    conn.commit()

def load_register(register_file):
    register = configparser.ConfigParser()
    register.read(register_file)
    
    valid_hosts = {}
    if 'valid_hosts' in register:
        for host, ports in register['valid_hosts'].items():
            valid_hosts[host] = set(ports.split(', '))
    
    return valid_hosts

def should_alert(domain, port, conn):
    """
    Query the database to check if a domain-port pair already exists.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM open_ports WHERE domain = ? AND port = ?", (domain, port))
    exists = cursor.fetchone()
    return exists is None

def validate_ports(input_file, valid_hosts, conn, output_file=None):
    """
    Validate ports against valid_hosts and database, generate alerts if needed.
    """
    alert = False
    output_data = []
    port_dict = []

    with open(input_file) as infile:
        for line in infile:
            try:
                domain, ports = line.strip().split('=')
                domain = domain.strip()
                ports = [port.strip() for port in ports.split(',')]
            except ValueError:
                click.echo(f"Invalid line format in formatted naabu file: {line.strip()}")
                continue

            if domain in valid_hosts:
                valid_port_set = set(valid_hosts[domain])  
                port_set = set(ports) - {'80', '443'}
                
                invalid_ports = port_set - valid_port_set
                if invalid_ports:
                    alert_message = f"ALERT: {domain} has unauthorized port(s) open - {', '.join(invalid_ports)}"
                    output_data.append(alert_message)
                    for port in invalid_ports:
                        port_dict.append((domain, port, alert_message))
                    alert = True
            else:
                unknown_ports = set(ports) - {'80', '443', '8080', '8443'}
                if unknown_ports:
                    alert_message = f"ALERT: Unknown domain {domain} with open port(s) {', '.join(unknown_ports)}"
                    output_data.append(alert_message)
                    for port in unknown_ports:
                        port_dict.append((domain, port, alert_message))
                    alert = True

    if port_dict:
        for domain, port, alert_message in port_dict:
            save_to_db(domain, port, alert_message, conn)
        if output_file:
            with open(output_file, 'a') as outfile:
                for alert_msg in output_data:
                    outfile.write(alert_msg + '\n')
        else:
            click.echo("\n".join(output_data))
    else:
        click.echo("No alert" if not alert else "No new alert, old alerts are in database")
