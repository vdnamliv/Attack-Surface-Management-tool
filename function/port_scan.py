import subprocess
import os
import click

TOOL_DIR = "./tools"

def run_naabu(input_file, output_file):
    click.echo("[INFO] Running naabu...")
    naabu_cmd = [os.path.join(TOOL_DIR, "naabu"), "-list", input_file, "-o", output_file]
    try:
        subprocess.run(naabu_cmd, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"[ERROR] Naabu failed: {e}")
        return False

    if not os.path.isfile(output_file):
        click.echo(f"[ERROR] Output file {output_file} was not created.")
        return False
    return True

def parse_naabu_output(input_file, output_file):
    port_dict = {}
    with open(input_file, "r") as infile:
        for line in infile:
            try:
                domain, port = line.strip().split(':')
                port_dict.setdefault(domain, []).append(port)
            except ValueError:
                click.echo(f"[WARNING] Invalid line: {line.strip()}")

    with open(output_file, "w") as outfile:
        for domain, ports in port_dict.items():
            outfile.write(f"{domain} = {', '.join(ports)}\n")

    return port_dict
