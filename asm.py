import click
import subprocess
import configparser
import os
import tempfile
import sqlite3
import schedule
import time
import re 
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from function.subdomain import (
    run_subfinder,
    run_sublist3r,
    run_assetfinder,
    run_securitytrails,
    merge_files,
)
from function.port_scan import run_naabu, parse_naabu_output
from function.alert import init_db, load_register, validate_ports
from function.email_alert import check_and_send_alert


# Configure logging
log_file = "asm_tool.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()  # Output logs to console
    ]
)

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Error occurred: {e}")
        exit(1)

def safe_run(func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except Exception as e:
        click.echo(f"Error running {func.__name__}: {e}")

def execute_scan(domain, port_scan, alert, output, email, conn):
    # Initialize database connection
    conn = init_db()

    # Load configuration
    register_file = "register.ini"
    valid_hosts = load_register(register_file)

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
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(safe_run, run_subfinder, domain, subfinder_file),
                    executor.submit(safe_run, run_sublist3r, domain, sublist3r_file),
                    executor.submit(safe_run, run_assetfinder, domain, assetfinder_file),
                    executor.submit(safe_run, run_securitytrails, domain, st_file)
                ]
                for future in futures:
                    future.result()  # Wait for all tasks to complete

            # Merge results
            merge_files(subfinder_file, sublist3r_file, assetfinder_file, st_file, subs_file)

            # If only "-s" (no "-p" or "-a")
            if not port_scan and not alert:
                if output:
                    with open(subs_file, 'r') as f, open(output, 'w') as o:
                        o.write(f.read())  # Write merged subdomains to output file
                else:
                    click.echo("You can specify an output file using -o to save subdomains.")

            # Port scanning if "-p" is specified
            if port_scan:
                click.echo(f"Starting port scan for subdomains in {subs_file}...")
                if not run_naabu(subs_file, naabu_raw_file):
                    click.echo("Naabu scan failed. Skipping port scanning step.")
                    return

                parse_naabu_output(naabu_raw_file, formatted_naabu_file)

                # Handle port scan output
                if output:
                    with open(formatted_naabu_file, 'r') as f, open(output, 'w') as o:
                        o.write(f.read())  # Write formatted results to output file
                    click.echo(f"Port scan results saved to {output}")
                else:
                    with open(formatted_naabu_file, 'r') as f:
                        click.echo(f.read())  # Print formatted results to terminal

        # Alert validation if "-a" is specified
        if alert:
            if os.path.exists(formatted_naabu_file):
                validate_ports(formatted_naabu_file, valid_hosts, conn, output)
            else:
                click.echo("No ports scanned or formatted_naabu_file is missing.")

        if email:
            try:
                check_and_send_alert()  # Check database and send email if alerts exist
            except Exception as e:
                logging.error(f"Failed to send email alert: {e}")

@click.command()
@click.option('-d', '--domain', type=str, help='Domain to scan for subdomains')
@click.option('-p', '--port-scan', is_flag=True, help='Perform port scan with naabu on subdomains')
@click.option('-a', '--alert', is_flag=True, help='Configuration file with valid hosts and ports')
@click.option('-o', '--output', type=click.Path(), help='File to save the final results')
@click.option('-e', '--email', is_flag=True, help='Send email alerts for detected issues')
@click.option("-t", "--interval-time", type=int, default=None, help="Set the interval time in seconds to run the scan automatically.")
@click.option('-f', '--file', type=click.Path(exists=True), help='File containing a list of domains to scan')
def main(domain, port_scan, alert, output, email, interval_time, file):
    conn = init_db()
    logging.info("ASM tool started")

    def scan_and_alert(target_domain):
        logging.info(f"Starting scan for domain: {target_domain}")
        try:
            execute_scan(domain=target_domain, port_scan=port_scan, alert=alert, output=output, email=email, conn=conn)
            logging.info(f"Scan completed successfully for domain: {target_domain}")
        except Exception as e:
            logging.error(f"Error during scan for domain {target_domain}: {e}")

    if file:
        with open(file, 'r') as f:
            domains = [line.strip() for line in f.readlines()]
        logging.info(f"Loaded {len(domains)} domains from file {file}")

        while True:
            for target_domain in domains:
                scan_and_alert(target_domain)
            logging.info(f"Waiting {interval_time} seconds for the next cycle...")
            time.sleep(interval_time)
    else:
        def single_scan():
            logging.info("Starting scan...")
            try:
                execute_scan(domain=domain, port_scan=port_scan, alert=alert, output=output, email=email, conn=conn)
                logging.info("Scan completed successfully.")
            except Exception as e:
                logging.error(f"Error during scan: {e}")

        if interval_time:
            while True:
                single_scan()
                logging.info(f"Waiting {interval_time} seconds for the next scan...")
                time.sleep(interval_time)
        else:
            single_scan()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Scan stopped by user.")
        sys.exit(0)
