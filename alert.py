import sqlite3
import configparser
from datetime import datetime
import click


# Thiết lập logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
"""
Logic kiem tra alert:
- dau tien kiem tra trong valid_hosts trong register.ini, neu trung het thi No Alert
- neu con host-port la. thi kiem tra tiep trong db --> trung het thi No new alert
- neu khong co trong db -->In ra Alert 
"""

def init_db(db_path="open_ports.db"):
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

#Save a new alert to the database or update an existing record.
def save_to_db(domain, port, alert_message, conn):
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

#Query the database to check if a domain-port pair already exists.
def should_alert(domain, port, conn):

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
                logging.warning(f"Invalid line format in formatted naabu file: {line.strip()}")
                click.echo(f"Invalid line format in formatted naabu file: {line.strip()}")
                continue

            port_set = set(ports) - {'80', '443', '8080', '8443'}  # Bỏ qua các cổng phổ biến
            if domain in valid_hosts:
                valid_port_set = set(valid_hosts[domain])
                invalid_ports = port_set - valid_port_set
                if invalid_ports:
                    for port in invalid_ports:
                        if should_alert(domain, port, conn):  # Kiểm tra database
                            alert_message = f"ALERT: {domain} has unauthorized port(s) open - {port}"
                            output_data.append(alert_message)
                            port_dict.append((domain, port, alert_message))
                            alert = True
            else:
                unknown_ports = port_set - {'8080', '8443'}  # Thêm cổng phổ biến khác nếu cần
                if unknown_ports:
                    for port in unknown_ports:
                        if should_alert(domain, port, conn):  # Kiểm tra database
                            alert_message = f"ALERT: Unknown domain {domain} with open port(s) {port}"
                            output_data.append(alert_message)
                            port_dict.append((domain, port, alert_message))
                            alert = True

    # Lưu dữ liệu nếu có alert
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
        # Nếu không có alert nào mới
        if not alert:
            logging.info("No alert")
            click.echo("No alert")
        else:
            logging.info("No new alert, old alerts are in database")
            click.echo("No new alert, old alerts are in database")

