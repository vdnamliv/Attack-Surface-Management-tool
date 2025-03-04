import os
import subprocess
import logging
import click

log_file = "asm_tool.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Đường dẫn thư mục chứa các tool
TOOL_DIR = "./tools"

def run_command(command, tool_name):
    """Thực thi lệnh và xử lý lỗi chung cho các tool."""
    try:
        subprocess.run(command, check=True)
        logging.info(f"{tool_name} completed successfully.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Error running {tool_name}: {e}")
        logging.error(f"{tool_name} failed: {e}")
    except Exception as e:
        click.echo(f"Unexpected error while running {tool_name}: {e}")
        logging.error(f"Unexpected error while running {tool_name}: {e}")

def run_subfinder(domain, output_file):
    click.echo(f"Running Subfinder on {domain}...")
    logging.info(f"Starting Subfinder on {domain}...")
    
    command = [os.path.join(TOOL_DIR, "subfinder"), "-d", domain, "-o", output_file]
    run_command(command, "Subfinder")

def run_sublist3r(domain, output_file):
    click.echo(f"Running Sublist3r on {domain}...")
    logging.info(f"Starting Sublist3r on {domain}...")
    
    sublist3r_path = os.path.join(TOOL_DIR, "Sublist3r", "sublist3r.py")
    command = ["python3", sublist3r_path, "-d", domain, "-o", output_file]
    run_command(command, "Sublist3r")

def run_assetfinder(domain, output_file):
    click.echo(f"Running Assetfinder on {domain}...")
    logging.info(f"Starting Assetfinder on {domain}...")
    
    command = [os.path.join(TOOL_DIR, "assetfinder"), "--subs-only", domain]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, stdout=f, check=True)
            logging.info("Assetfinder completed successfully.")
    except subprocess.CalledProcessError as e:
        click.echo(f"Error running Assetfinder: {e}")
        logging.error(f"Assetfinder failed: {e}")
    except Exception as e:
        click.echo(f"Unexpected error while running Assetfinder: {e}")
        logging.error(f"Unexpected error while running Assetfinder: {e}")

def run_securitytrails(domain, output_file):
    click.echo(f"Running SecurityTrails on {domain}...")
    logging.info(f"Starting SecurityTrails on {domain}...")

    st_script_path = os.path.join(TOOL_DIR, "security-trails", "securitytrails.py")
    command = ["python3", st_script_path, "-d", domain]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        
        with open(output_file, 'w') as f:
            f.write("\n".join(subdomains))

        logging.info("SecurityTrails completed successfully.")
    except subprocess.CalledProcessError as e:
        click.echo("Error: SecurityTrails command execution failed.")
        logging.error(f"SecurityTrails failed: {e}")
    except Exception as e:
        click.echo(f"Unexpected error while running SecurityTrails: {e}")
        logging.error(f"Unexpected error while running SecurityTrails: {e}")

def merge_files(sub_files, output_file):
    """Hợp nhất kết quả từ nhiều file subdomain thành một file duy nhất."""
    click.echo(f"Merging subdomain results into {output_file}...")
    logging.info("Merging subdomain results...")

    subdomains = set()

    for tool, file_path in sub_files.items():
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                lines = [line.strip() for line in f.readlines()]
                subdomains.update(lines)
        else:
            warning_msg = f"Warning: {file_path} not found, skipping {tool} results."
            click.echo(warning_msg)
            logging.warning(warning_msg)

    with open(output_file, 'w') as f:
        f.write("\n".join(sorted(subdomains)))

    click.echo(f"Merged results saved to {output_file}.")
    logging.info(f"Merged results saved to {output_file}.")

def run_all_subdomain_tools(domain, sub_files):
    run_subfinder(domain, sub_files["subfinder"])
    run_sublist3r(domain, sub_files["sublist3r"])
    run_assetfinder(domain, sub_files["assetfinder"])
    run_securitytrails(domain, sub_files["securitytrails"])
