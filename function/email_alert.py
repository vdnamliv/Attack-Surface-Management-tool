import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import sqlite3
import configparser
import os

config = configparser.ConfigParser()
config.read("config.ini")

ALERT_EMAIL = config.get("email", "alert_email")
SMTP_SERVER = config.get("email", "smtp_server")
SMTP_PORT = int(config.get("email", "smtp_port"))
SMTP_USER = config.get("email", "smtp_user")
SMTP_PASSWORD = config.get("email", "smtp_password")
DB_PATH = config.get("path", "path_db")

def send_email_alert(subject, message):
    """Send an alert email using smtplib."""
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())

        logging.info(f"Alert email sent to {ALERT_EMAIL}.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def check_and_send_alert():
    """Check the database for alerts and send email if needed."""
    if not os.path.exists(DB_PATH):
        logging.error(f"Database not found at {DB_PATH}.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT domain, port, alert_message FROM open_ports WHERE alert_message IS NOT NULL")
        alerts = cursor.fetchall()

        if alerts:
            alert_message = "ALERT: The following hosts and ports have issues:\n"
            for domain, port, alert_message in alerts:
                alert_message += f"{domain}:{port} - {alert_message}\n"

            send_email_alert("Security Alert - Open Ports", alert_message)

        else:
            logging.info("No alert to send.")
    except Exception as e:
        logging.error(f"Error while querying alerts: {e}")
    finally:
        if conn:
            conn.close()
