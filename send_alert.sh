#!/bin/bash

# Load parameters from config.ini
CONFIG_FILE="config.ini"
MAIL_TO=$(grep -Po '(?<=^MAIL_TO = ).*' "$CONFIG_FILE")
MAIL_SUBJECT=$(grep -Po '(?<=^MAIL_SUBJECT = ).*' "$CONFIG_FILE")
RECENT_TIME=$(grep -Po '(?<=^RECENT_TIME = ).*' "$CONFIG_FILE")
TIMEOUT=$(grep -Po '(?<=^TIMEOUT = ).*' "$CONFIG_FILE")
DATABASE_PATH=$(grep -Po '(?<=^DATABASE_PATH = ).*' "$CONFIG_FILE")

send_email() {
    local alert_message=$1
    echo -e "Subject: $MAIL_SUBJECT\n\n$alert_message" | msmtp "$MAIL_TO"
}

CURRENT_TIME=$(date +%s)

query_alerts() {
    sqlite3 "$DATABASE_PATH" "SELECT domain, port, alert_message, scan_date FROM open_ports WHERE alert_message IS NOT NULL;" |
    while IFS="|" read -r domain port alert_message scan_date; do
        TIME_DIFFERENCE=$((CURRENT_TIME - scan_date))
        
        if [ "$TIME_DIFFERENCE" -le "$RECENT_TIME" ]; then
            alert="$alert_message"
            echo "$alert"
            send_email "$alert"
        
        elif [ "$TIME_DIFFERENCE" -ge "$TIMEOUT" ]; then
            alert="OLD alert: $alert_message"
            echo "$alert"
            send_email "$alert"
        fi
    done
}

query_alerts
