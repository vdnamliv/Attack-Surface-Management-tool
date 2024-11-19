import click
import subprocess
import configparser
import os
import tempfile
import sqlite3
import schedule
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Error occurred: {e}")
        exit(1)

def run_subfinder(domain, output_file):
    try:
        click.echo(f"Running Subfinder on {domain}...")
        subfinder_cmd = f"subfinder -d {domain} --all --recursive -o {output_file}"
        subprocess.run(subfinder_cmd, shell=True, check=True)
    except Exception as e:
        click.echo(f"Error running Subfinder: {e}")

def run_sublist3r(domain, output_file, path_sublist3r):
    try:
        click.echo(f"Running Sublist3r on {domain}...")
        sublist3r_cmd = f"python3 {path_sublist3r} -d {domain} -o {output_file}"
        subprocess.run(sublist3r_cmd, shell=True, check=True)
    except Exception as e:
        click.echo(f"Error running Sublist3r: {e}")

def run_assetfinder(domain, output_file):
    try:
        click.echo(f"Running Assetfinder on {domain}...")
        assetfinder_cmd = f"assetfinder --subs-only {domain} > {output_file}"
        subprocess.run(assetfinder_cmd, shell=True, check=True)
    except Exception as e:
        click.echo(f"Error running Assetfinder: {e}")

def run_securitytrails(domain, output_file, path_st, api_key_st):
    if not api_key_st:
        click.echo("No valid SecurityTrails API key found, skipping SecurityTrails scan.")
        return None

    try:
        click.echo(f"Running SecurityTrails on {domain}...")
        st_cmd = f"python3 {path_st} -d {domain} -k {api_key_st} > {output_file}"
        run_command(st_cmd)
    except subprocess.CalledProcessError:
        click.echo("Error: SecurityTrails command failed or API key may have expired.")
        return None

def merge_files(file1, file2, file3, file4, output_file):
    subdomains = set()
    for fname in [file1, file2, file3, file4]:
        if os.path.exists(fname): 
            with open(fname) as infile:
                for line in infile:
                    subdomains.add(line.strip())
        else:
            print(f"Warning: {fname} not found, skipping...")

    with open(output_file, 'w') as outfile:
        for subdomain in subdomains:
            outfile.write(subdomain + '\n')

def run_naabu(input_file, output_file):
    click.echo("Running naabu scan...")
    naabu_cmd = f"naabu -list {input_file} -o {output_file}"
    try:
        subprocess.run(naabu_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Error occurred during naabu scan: {e}")
        return False

    if not os.path.isfile(output_file):
        click.echo(f"Error: Output file {output_file} was not created.")
        return False
    return True

def parse_naabu_output(input_file, output_file):
    port_dict = {}
    with open(input_file) as infile:
        for line in infile:
            try:
                domain, port = line.strip().split(':')
                if domain not in port_dict:
                    port_dict[domain] = []
                port_dict[domain].append(port)
            except ValueError:
                click.echo(f"Invalid line in naabu output: {line.strip()}")

    with open(output_file, 'w') as outfile:
        for domain, ports in port_dict.items():
            result_line = f"{domain} = {', '.join(ports)}"
            outfile.write(result_line + '\n')

    # Optionally, echo the result
    for domain, ports in port_dict.items():
        result_line = f"{domain} = {', '.join(ports)}"
        click.echo(result_line)

    return port_dict


"""
Ta se build open_ports.db
- open_ports: domain, port, scan_date, alert_message --> luu cac host-port khong co trong config.ini
- scan_date: luu thoi gian cac alert (chi alert thoi gian 5 phut truoc, hoac qua 24h)
- alert_message: mau alert
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

def save_to_db(domain, port, alert_message, conn):
    cursor = conn.cursor()
    scan_date = int(datetime.now().timestamp())
    cursor.execute("""
        INSERT INTO open_ports (domain, port, scan_date, alert_message) 
        VALUES (?, ?, ?, ?) 
        ON CONFLICT(domain, port) DO UPDATE SET scan_date=excluded.scan_date, alert_message=excluded.alert_message
    """, (domain, port, scan_date, alert_message))
    conn.commit()

def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    valid_hosts = {}
    if 'valid_hosts' in config:
        for host, ports in config['valid_hosts'].items():
            valid_hosts[host] = set(ports.split(', '))

    path_sublist3r = config.get('path', 'path_sublist3r', fallback=None)
    path_st = config.get('path', 'path_st', fallback=None)
    api_key_st = config.get('path', 'api_key_st', fallback=None)

    return valid_hosts, path_sublist3r, path_st, api_key_st

#querry db to check domain-port exist ?
def should_alert(domain, port, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM open_ports WHERE domain = ? AND port = ?", (domain, port))
    exists = cursor.fetchone()
    return exists is None  

"""
Logic kiem tra alert:
- dau tien kiem tra trong valid_hosts trong config.ini, neu trung het thi No Alert
- neu con host-port la. thi kiem tra tiep trong db --> trung het thi No new alert
- neu khong co trong db -->In ra Alert 
"""
def validate_ports(input_file, valid_hosts, conn, output_file=None):
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

def execute_scan(domain, port_scan, alert, output, conn): 
    # Initialize database connection
    conn = init_db()

    # Load configuration
    config_file = "config.ini"
    valid_hosts, path_sublist3r, path_st, api_key_st = load_config(config_file)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Define temporary file paths
        subfinder_file = os.path.join(tmpdir, "subfinder.txt")
        sublist3r_file = os.path.join(tmpdir, "sublist3r.txt")
        assetfinder_file = os.path.join(tmpdir, "assetfinder.txt")
        st_file = os.path.join(tmpdir, "securitytrails.txt")
        subs_file = os.path.join(tmpdir, "Subs.txt")
        naabu_raw_file = os.path.join(tmpdir, "naabu_raw.txt")
        formatted_naabu_file = os.path.join(tmpdir, "formatted_naabu.txt")

        # Subdomain enumeration if "-s" is specified
        if domain:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(safe_run, run_subfinder, domain, subfinder_file),
                    executor.submit(safe_run, run_sublist3r, domain, sublist3r_file, path_sublist3r),
                    executor.submit(safe_run, run_assetfinder, domain, assetfinder_file),
                    executor.submit(safe_run, run_securitytrails, domain, st_file, path_st, api_key_st)
                ]
                for future in futures:
                    future.result()  # Wait for all tasks to complete

            # Merge results
            merge_files(subfinder_file, sublist3r_file, assetfinder_file, st_file, subs_file)

            # If only "-s" (no "-p" or "-a")
            if not port_scan and not alert:
                if output:
                    with open(subs_file, 'r') as f, open(output, 'w') as o:
                        o.write(f.read())
                else:
                    click.echo("You can specify an output file using -o.")

            # Port scanning if "-p" is specified
            if port_scan:
                run_naabu(subs_file, naabu_raw_file)
                parse_naabu_output(naabu_raw_file, formatted_naabu_file)

        # Alert validation if "-a" is specified
        if alert:
            if os.path.exists(formatted_naabu_file):
                validate_ports(formatted_naabu_file, valid_hosts, conn, output)
            else:
                click.echo("No ports scanned or formatted_naabu_file is missing.")

def safe_run(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except Exception as e:
        click.echo(f"Error running {func.__name__}: {e}")


@click.command()
@click.option('-d', '--domain', type=str, help='Domain to scan for subdomains')
@click.option('-p', '--port-scan', is_flag=True, help='Perform port scan with naabu on subdomains')
@click.option('-a', '--alert', is_flag=True, help='Configuration file with valid hosts and ports')
@click.option('-o', '--output', type=click.Path(), help='File to save the final results')
@click.option('-t', '--set-time', type=int, help='Run tool automatically every specified minutes')

def main(domain, port_scan, alert, output, set_time):
    conn = init_db()

    def run_tool():
        print("Starting scan...")
        safe_run(execute_scan, domain=domain, port_scan=port_scan, alert=alert, output=output, conn=conn)

    # if "-t"
    if set_time:
        schedule.every(set_time).minutes.do(run_tool)
        print(f"Scheduled scan every {set_time} minutes...")

        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        run_tool()

if __name__ == "__main__":
    main()
