import os
import subprocess
import re
import click
import configparser

config = configparser.ConfigParser()
config.read("config.ini")

PATH_SUBLIST3R = config.get("path", "path_sublist3r")
PATH_ST = config.get("path", "path_st")
API_KEY_ST = config.get("path", "api_key_st")

def run_subfinder(domain, output_file):
    try:
        click.echo(f"Running Subfinder on {domain}...")
        subfinder_cmd = f"subfinder -d {domain} --all --recursive -o {output_file}"
        subprocess.run(subfinder_cmd, shell=True, check=True)
    except Exception as e:
        click.echo(f"Error running Subfinder: {e}")

def run_sublist3r(domain, output_file):
    try:
        click.echo(f"Running Sublist3r on {domain}...")
        sublist3r_cmd = f"python3 {PATH_SUBLIST3R} -d {domain} -o {output_file}"
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

def run_securitytrails(domain, output_file):
    if not api_key_st:
        click.echo("No valid SecurityTrails API key found, skipping SecurityTrails scan.")
        return None

    try:
        click.echo(f"Running SecurityTrails on {domain}...")
        st_cmd = f"python3 {PATH_ST} -d {domain} -k {API_KEY_ST}"
        result = subprocess.run(st_cmd, shell=True, text=True, capture_output=True)

        if result.returncode != 0:
            click.echo("Error: SecurityTrails command failed or API key may have expired.")
            return None

        subdomain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        subdomains = [
            line.strip() for line in result.stdout.splitlines() 
            if subdomain_regex.match(line.strip())
        ]

        with open(output_file, 'w') as outfile:
            outfile.write("\n".join(subdomains))
    except subprocess.CalledProcessError:
        click.echo("Error: SecurityTrails command execution failed.")
        return None

def merge_files(file1, file2, file3, file4, output_file):
    subdomain_regex = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    subdomains = set()
    for fname in [file1, file2, file3, file4]:
        if os.path.exists(fname):
            with open(fname) as infile:
                for line in infile:
                    subdomain = line.strip()
                    if subdomain_regex.match(subdomain):
                        subdomains.add(subdomain)
        else:
            print(f"Warning: {fname} not found, skipping...")

    with open(output_file, 'w') as outfile:
        for subdomain in sorted(subdomains):  
            outfile.write(subdomain + '\n')
