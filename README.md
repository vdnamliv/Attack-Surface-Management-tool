# Automated Attack Surface Management Tool

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
To avoid email "bombs", I stored the sent alerts in a simple SQLite database (alert.db).
2. Change config.ini
Change "your_gmail" and "your_app_password", if don't know how to create app password, go [here](https://myaccount.google.com/apppasswords?pli=1&rapt=AEjHL4OVlHBZyIzfrw29E_Q4mYB5-Ei_wmrnL7Bw5Mvr51ST_6r9yfNADQL6wxYkdzGYKzB5DULwwhRcJaOEfKjloUDyhUbRCHUonLcj99aCP6EDXzOBBFM)

3. Send alert to your email:
For example, you want to run the tool periodically once a day:
```
python3 asm.py -d <domain name> -p -a -t 86400 
```
And done!!!
