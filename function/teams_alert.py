import requests
import logging
import sqlite3

class TeamsAlert:
    """
    A reusable module for sending alerts to Microsoft Teams via webhook.
    """
    DB_PATH = "/home/vdnam/Desktop/asm/open_ports.db"
    
    def __init__(self, webhook_url, mention_id, mention_name):
        """
        Initialize the TeamsAlert class with provided parameters.

        Args:
            webhook_url (str): Microsoft Teams webhook URL.
            mention_id (str): MS Teams user ID of the user to be mentioned.
            mention_name (str): Display name of the user to be mentioned.
        """
        self.webhook_url = webhook_url
        self.mention_id = mention_id
        self.mention_name = mention_name

    def send_alert(self):
        """
        Send a notification message to Microsoft Teams.
        """
        try:
            # Use self.DB_PATH to refer to the database path
            conn = sqlite3.connect(self.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("SELECT alert_message FROM open_ports WHERE alert_message IS NOT NULL")
            alerts = [row[0] for row in cursor.fetchall()]  # Fetch all alert messages
            
            conn.close()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            alerts = []
        except Exception as e:
            print(f"Unexpected error: {e}")
            alerts = []

        # Build the mention part
        mentions = [
            {
                "type": "mention",
                "text": f"<at>{self.mention_name}</at>",
                "mentioned": {
                    "id": self.mention_id,
                    "name": self.mention_name
                }
            }
        ]

        # Build the payload to send to Teams
        headers = {"Content-Type": "application/json"}
        body = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Medium",
                                "weight": "Bolder",
                                "text": "Important Notification"
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Alerts: {', '.join(alerts) if alerts else 'No alerts found.'}"
                            },
                            {
                                "type": "TextBlock",
                                "text": f"Hi <at>{self.mention_name}</at>"
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.0",
                        "msteams": {
                            "entities": mentions
                        }
                    }
                }
            ]
        }

        # Send the request to the webhook
        try:
            response = requests.post(self.webhook_url, headers=headers, json=body)
            if 200 <= response.status_code <= 299:
                logging.info(f"Alert sent successfully. Status code: {response.status_code}")
            else:
                logging.error(f"Error: Failed to send alert. Status code: {response.status_code}")
        except requests.RequestException as e:
            logging.error(f"Error: Failed to send alert due to {e}")


