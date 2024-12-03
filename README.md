# Automated Attack Surface Management Tool (LINUX)

## Feature:
- Find **all subdomains** and scan **opening ports** on them from an input domain name or IPs list.
- Allows users to provide a **configuration file** (registered hosts + ports). 
- If a host is found to have an unregistered port open when scanning --> **Alert** 
- If a host is not in the configuration file but has ports other than 80 & 443 open --> **Alert**
- Automatically scan after a certain period of time.
- Send alert to administrator's email, will not resend duplicate alerts.

## How it works:
- This is a series of tool commands run one after another to produce the final result of subdomains with open ports.
- The user enters input using the command line or configuration and IPs files
- Uses Subfinder, Sublist3r, Assetfinder, Security-trails, Naabu
- Combines results of subdomains and opening ports from all tools to terminal or a single file

## Installation:
1. Install python, go and git (if not already)
```
sudo apt update
sudo apt install python3 python3-pip -y
sudo apt install golang-go
sudo apt install git
```
2. Install tool and run the setup.sh:
```
git clone https://github.com/vdnamliv/Attack-Surface-Management-tool
```
```
cd Attack-Surface-Management-tool
chmod +x setup.sh
./setup.sh
```

## Usage:
  You can change your Securitytrails API key and registered host-port in config.ini
  ### Summary of <code>option</code> flag

| Option      | Description                                           | Example Command                                           |
|-------------|-------------------------------------------------------|----------------------------------------------------------|
| `-d`      | Use Subfinder, Sublist3r, Assetfinder and Security-trails API to scan for subdomain   | `python3 asm.py -d <domain name> ` |
| `-f` | Multiple Domain Input for scan subdomain | `python3 asm.py -f <domain file txt>` |
| `-p`      | Perform opening port scan with Naabu on subdomains      | `python3 asm.py -d <domain name> -p` |
| `-a` | Get valid host-port data from config.ini, compare with scanned host-ports and ALERT if there is a difference | `python3 asm.py -d <domain name> -p -a` |
| `-e` | Send those ALERT to your email | `python3 asm.py -d <domain name> -p -a -e` |
| `-t` | Run tool automatically every specified seconds | `python3 asm.py -d <domain name> -p -a -t 86400` |


## Step by step to use ALERT (-a) function
1. Scan all subdomain and open port in your domain:
```
python3 asm.py -d <domain name> -p -o domain.txt
```
2. Use domain.txt data (host: port) copy to "valid_hosts" section in register.ini as a baseline 
example:
```
subdomain1.domain.com: 25, 445
subdomain2.domain.com: 515, 445
```
3. Check again to see if there is an alert (subdomain, port not found yet):
```
python3 asm.py -d <domain name> -p -a 
```
or automatically scan the tool (For example, scan once a day):
```
python3 asm.py -d <domain name> -p -a -t 86400
```

## Step by step to send ALERT to email
1. Using database to save exist alert:
- To avoid email "bombs", I stored the sent alerts in a simple SQLite database (alert.db).
2. Change config.ini
- Change "your_gmail" and "your_app_password", if don't know how to create app password, go [here](https://myaccount.google.com/apppasswords?pli=1&rapt=AEjHL4OVlHBZyIzfrw29E_Q4mYB5-Ei_wmrnL7Bw5Mvr51ST_6r9yfNADQL6wxYkdzGYKzB5DULwwhRcJaOEfKjloUDyhUbRCHUonLcj99aCP6EDXzOBBFM)

3. Send alert to your email:
- For example, you want to run the tool periodically once a day:
```
python3 asm.py -d <domain name> -p -a -t 86400 
```
And done!!!

## Step by step to AUTOMATICALLY run ASM tool 24/7 (Scan subdomain and port, alert, send alert email to admin):
1. Build your Domain list to scan. (domain.txt)
2. Config as "send ALERT to email" path above
3. Scan here:
```
python3 asm.py -f <domain file txt> -p -a -t 86400 
```
4.See log info in asm_tool.log:
- For example:
```
2024-12-03 12:20:55,929 [INFO] Starting scan for domain: google.com
2024-12-03 12:22:38,916 [INFO] Scan completed successfully for domain: google.com
2024-12-03 12:22:38,916 [INFO] Starting scan for domain: youtube.com
2024-12-03 12:23:30,076 [INFO] Scan completed successfully for domain: youtube.com
2024-12-03 12:23:30,076 [INFO] Waiting 86400 seconds for the next cycle...
```
