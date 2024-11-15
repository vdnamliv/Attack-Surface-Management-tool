# Automated Subdomain Enumeration and Port Scanning Tool

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
1. Install python and git (if not already)
```
sudo apt update
sudo apt install python3 python3-pip -y
sudo apt install git
```
2. Install tool and run the setup.sh:
```
git clone https://github.com/vdnamliv/Attack-Surface-Management-tool
```
```
cd asm
chmod +x setup.sh
./setup.sh
```

## Usage:
  You can change your Securitytrails API key and registered host-port in config.ini
  ### Summary of <code>option</code> flag

| Option      | Description                                           | Example Command                                           |
|-------------|-------------------------------------------------------|----------------------------------------------------------|
| `-d`      | Use Subfinder, Sublist3r, Assetfinder and Security-trails API to scan for subdomain   | `python3 asm.py -d <domain name> ` |
| `-p`      | Perform opening port scan with Naabu on subdomains      | `python3 asm.py -d <domain name> -p` |
| `-a` | Get valid host-port data from config.ini, compare with scanned host-ports and ALERT if there is a difference | `python3 asm.py -d <domain name> -p -a` |
| `-t` | Run tool automatically every specified minutes | `python3 asm.py -d <domain name> -p -a -t 5` |

## Step by step to send ALERT to email
1. Using database to save exist alert:
To avoid email "bombs", I stored the sent alerts in a simple SQLite database (alert.db).
2. Using msmtp to send Alert to email: 
Open hidden file .msmtprc:
```
nano ~/Attack-Surface-Management-tool/.msmtprc
```
Change "your_gmail" and "your_app_password", if don't know how to create app password, go [hear](https://myaccount.google.com/apppasswords?pli=1&rapt=AEjHL4OVlHBZyIzfrw29E_Q4mYB5-Ei_wmrnL7Bw5Mvr51ST_6r9yfNADQL6wxYkdzGYKzB5DULwwhRcJaOEfKjloUDyhUbRCHUonLcj99aCP6EDXzOBBFM)

Send alert to your email:
```
./send_alert.sh
```
And done!!!
