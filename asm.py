import click
import logging
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from function.subdomain import (
    run_subfinder,
    run_sublist3r,
    run_assetfinder,
    run_securitytrails,
    merge_files,
)
from function.port_scan import run_naabu, parse_naabu_output
from function.alert import init_alert_db, load_register, validate_host_ports  # Giữ nếu bạn cần alert

TOOL_DIR = "./tools"
LOG_FILE = "asm_tool.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)

@click.command()
@click.option('-d', '--domain', type=str, help='Domain to scan for subdomains')
@click.option('-p', '--port-scan', is_flag=True, help='Perform port scan with naabu on subdomains')
@click.option('-v', '--vul', is_flag=True, help='(Removed - Currently unused)')
@click.option('-a', '--alert', is_flag=True, help='Validate results against registered hosts and ports')
@click.option('-o', '--output', type=click.Path(), help='File to save the final results')
@click.option('-e', '--email', is_flag=True, help='(Removed - Currently unused)')
@click.option('--teams', is_flag=True, help='(Removed - Currently unused)')
@click.option('-t', '--interval-time', type=int, default=None, help='Interval time in seconds for repeated scans')
@click.option('-f', '--file', type=click.Path(exists=True), help='File containing multiple domains to scan')
def main(domain, port_scan, vul, alert, output, email, teams, interval_time, file):
    conn = init_alert_db()  # Nếu bạn vẫn giữ alert thì giữ phần này

    def run_scan(domain):
        tmp_dir = "temp"
        os.makedirs(tmp_dir, exist_ok=True)

        sub_files = {
            "subfinder": os.path.join(tmp_dir, "subfinder.txt"),
            "sublist3r": os.path.join(tmp_dir, "sublist3r.txt"),
            "assetfinder": os.path.join(tmp_dir, "assetfinder.txt"),
            "securitytrails": os.path.join(tmp_dir, "securitytrails.txt")
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(run_subfinder, domain, sub_files["subfinder"]),
                executor.submit(run_sublist3r, domain, sub_files["sublist3r"]),
                executor.submit(run_assetfinder, domain, sub_files["assetfinder"]),
                executor.submit(run_securitytrails, domain, sub_files["securitytrails"])
            ]

            for future in as_completed(futures):
                future.result()

        merged_file = os.path.join(tmp_dir, "merged_subdomains.txt")
        merge_files(sub_files, merged_file)

        if output:
            os.rename(merged_file, output)

        if port_scan:
            naabu_raw = os.path.join(tmp_dir, "naabu_raw.txt")
            naabu_formatted = os.path.join(tmp_dir, "naabu_formatted.txt")

            if run_naabu(merged_file, naabu_raw):
                parse_naabu_output(naabu_raw, naabu_formatted)

                if output:
                    with open(naabu_formatted, "r") as src, open(output, "a") as dest:
                        dest.write("\n")
                        dest.write(src.read())

        if alert:
            valid_hosts = load_register("register.ini")
            if os.path.exists(naabu_formatted):
                validate_host_ports(naabu_formatted, valid_hosts, conn, output)

    if file:
        with open(file, 'r') as f:
            domains = [line.strip() for line in f.readlines()]

        while True:
            for domain in domains:
                run_scan(domain)
            if interval_time:
                time.sleep(interval_time)
            else:
                break
    else:
        if interval_time:
            while True:
                run_scan(domain)
                time.sleep(interval_time)
        else:
            run_scan(domain)

if __name__ == "__main__":
    main()
