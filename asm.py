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
    click.echo(f"Running subfinder on {domain}...")
    subfinder_cmd = f"subfinder -d {domain} --all --recursive -o {output_file}"
    run_command(subfinder_cmd)

def run_sublist3r(domain, output_file, path_sublist3r):
    click.echo(f"Running Sublist3r on {domain}...")
    sublist3r_cmd = f"python3 {path_sublist3r} -d {domain} -o {output_file}"
    run_command(sublist3r_cmd)

def run_assetfinder(domain, output_file):
    click.echo(f"Running assetfinder on {domain}...")
    assetfinder_cmd = f"assetfinder --subs-only {domain} > {output_file}"
    run_command(assetfinder_cmd)

def run_securitytrails(domain, output_file, path_st, api_key_st):
    click.echo(f"Running SecurityTrails on {domain}...")
    st_cmd = f"python3 {path_st} -d {domain} -k {api_key_st} > {output_file}"
    run_command(st_cmd)

def merge_files(file1, file2, file3, file4, output_file):
    subdomains = set()
    for fname in [file1, file2, file3, file4]:
        with open(fname) as infile:
            for line in infile:
                subdomains.add(line.strip())
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

def parse_naabu_output(input_file):
    port_dict = {}
    with open(input_file) as infile:
        for line in infile:
            domain, port = line.strip().split(':')
            if domain not in port_dict:
                port_dict[domain] = []
            port_dict[domain].append(port)

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
    cursor.execute('''CREATE TABLE IF NOT EXISTS open_ports (
                        domain TEXT,
                        port TEXT,
                        scan_date TIMESTAMP,
                        alert_message TEXT,
                        PRIMARY KEY (domain, port)
                     )''')
    conn.commit()
    return conn

def save_to_db(domain, port, alert_message, conn):
    cursor = conn.cursor()
    scan_date = int(datetime.now().timestamp()) 
    cursor.execute("REPLACE INTO open_ports (domain, port, scan_date, alert_message) VALUES (?, ?, ?, ?)",
                   (domain, port, scan_date, alert_message))
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
def should_alert(domain, port, alert_message, conn, update_db=False):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM open_ports WHERE domain = ? AND port = ?", (domain, port))
    exists = cursor.fetchone()

    if not exists:
        if update_db:
            scan_date = int(datetime.now().timestamp())
            cursor.execute("INSERT INTO open_ports (domain, port, scan_date) VALUES (?, ?, ?)", 
                           (domain, port, scan_date))
            conn.commit()
        return True  
    return False  

def validate_ports(input_file, valid_hosts, conn, output_file=None):
    alert = False
    output_data = []
    port_dict = []

    with open(input_file) as infile:
        for line in infile:
            domain, port = line.strip().split(':')
            port = port.strip()
            if domain in valid_hosts:
                if port not in valid_hosts[domain]:
                    alert_message = f"ALERT: {domain} has unauthorized port open - {port}"
                    output_data.append(alert_message)
                    port_dict.append((domain, port, alert_message))
                    alert = True
            else:
                if port not in {'80', '443'}:
                    alert_message = f"ALERT: Unknown domain {domain} with open port {port}"
                    output_data.append(alert_message)
                    port_dict.append((domain, port, alert_message))
                    alert = True

    # Save to database
    for domain, port, alert_message in port_dict:
        save_to_db(domain, port, alert_message, conn)  # Save each record individually

    if output_file:
        with open(output_file, 'a') as outfile:
            for alert_msg in output_data:
                outfile.write(alert_msg + '\n')
    elif output_data:
        click.echo("\n".join(output_data))
    else:
        click.echo("No unauthorized ports detected.")

def run_nuclei_for_chunk(subdomains_chunk, output_file=None, concurrency=10, rate=20):
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as temp_file:
        temp_file_name = temp_file.name
        temp_file.writelines(f"{subdomain}\n" for subdomain in subdomains_chunk)
    
    nuclei_cmd = f"nuclei -l {temp_file_name} -c {concurrency} -rl {rate}"
    if output_file:
        nuclei_cmd += f" -o {output_file}"
    run_command(nuclei_cmd)
    
    os.remove(temp_file_name)

def run_nuclei(input_file, output_file=None, concurrency=10, rate=20, num_threads=4):
    click.echo("Checking for live subdomains...")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as alive_file:
        alive_subdomains = alive_file.name

    # use httpx to check alive subdomain 
    httpx_cmd = f"cat {input_file} | httpx-toolkit -sc | sed 's/ \\[.*//g' > {alive_subdomains}"
    run_command(httpx_cmd)
    
    click.echo("Splitting live subdomains and running Nuclei vulnerability scan in parallel...")
    
    with open(alive_subdomains, 'r') as file:
        all_subdomains = [line.strip() for line in file.readlines()]
    
    chunk_size = max(1, len(all_subdomains) // num_threads)
    subdomains_chunks = [all_subdomains[i:i + chunk_size] for i in range(0, len(all_subdomains), chunk_size)]
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(run_nuclei_for_chunk, chunk, output_file, concurrency, rate) for chunk in subdomains_chunks]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                click.echo(f"Error during scan: {e}", err=True)

    os.remove(alive_subdomains)

def execute_scan(domain, port_scan, config, output, vuln_scan):
    conn = init_db()
    config_file = "config.ini" if config else None
    valid_hosts, path_sublist3r, path_st, api_key_st = load_config(config_file) 

    with tempfile.TemporaryDirectory() as tmpdir:
        subfinder_file = os.path.join(tmpdir, "subfinder.txt")
        sublist3r_file = os.path.join(tmpdir, "sublist3r.txt")
        assetfinder_file = os.path.join(tmpdir, "assetfinder.txt")
        st_file = os.path.join(tmpdir, "securitytrails.txt")
        subs_file = os.path.join(tmpdir, "Subs.txt")
        naabu_file = os.path.join(tmpdir, "naabu.txt")

        # If "-s"
        if domain:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(run_subfinder, domain, subfinder_file),
                    executor.submit(run_sublist3r, domain, sublist3r_file, path_sublist3r),
                    executor.submit(run_assetfinder, domain, assetfinder_file),
                    executor.submit(run_securitytrails, domain, st_file, path_st, api_key_st)
                ]
                for future in futures:
                    future.result()
            merge_files(subfinder_file, sublist3r_file, assetfinder_file, st_file, subs_file)

            if not port_scan and not config and not vuln_scan:
                if output:
                    with open(subs_file, 'r') as f, open(output, 'w') as o:
                        o.write(f.read())
                else:
                    click.echo("You can specify an output file with using -o.")

            # If "-p"
            if port_scan:
                run_naabu(subs_file, naabu_file)
                parse_naabu_output(naabu_file)

            # If "-v"
            if vuln_scan:
                run_nuclei(subs_file, output)

        # If "-c"
        if config:
            valid_hosts = load_config(config_file)
            validate_ports(naabu_file, valid_hosts, conn, output)

@click.command()
@click.option('-d', '--domain', type=str, help='Domain to scan for subdomains')
@click.option('-p', '--port-scan', is_flag=True, help='Perform port scan with naabu on subdomains')
@click.option('-c', '--config', is_flag=True, help='Configuration file with valid hosts and ports')
@click.option('-o', '--output', type=click.Path(), help='File to save the final results')
@click.option('-v', '--vuln-scan', is_flag=True, help='Run Nuclei vulnerability scan on subdomains')
@click.option('-t', '--set-time', type=int, help='Run tool automatically every specified minutes')

def main(domain, port_scan, config, output, vuln_scan, set_time):
    def run_tool():
        print("Starting scan...")
        execute_scan(domain=domain, port_scan=port_scan, config=config, output=output, vuln_scan=vuln_scan)

    # If "-t"
    if set_time:
        schedule.every(set_time).minutes.do(run_tool)
        print(f"Scheduled scan every {set_time} minutes.")

        while True:
            schedule.run_pending()
            time.sleep(1)
    else:
        execute_scan(domain=domain, port_scan=port_scan, config=config, output=output, vuln_scan=vuln_scan)

if __name__ == "__main__":
    main()
