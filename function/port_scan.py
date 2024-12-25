import subprocess
import os
import click

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

    # for domain, ports in port_dict.items():
    #     result_line = f"{domain} = {', '.join(ports)}"
    #     click.echo(result_line)

    return port_dict
