import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import json

class NotificationManager:
    def __init__(self, config=None):
        self.config = config or {}
        self.email_enabled = self.config.get('email', {}).get('enabled', False)
        self.slack_enabled = self.config.get('slack', {}).get('enabled', False)
    
    def send_email_alert(self, subject, message, risk_level="MEDIUM"):
        if not self.email_enabled:
            return False
        
        email_config = self.config.get('email', {})
        smtp_server = email_config.get('smtp_server')
        smtp_port = email_config.get('smtp_port', 587)
        sender = email_config.get('sender')
        password = email_config.get('password')
        recipients = email_config.get('recipients', [])
        
        if not all([smtp_server, sender, password, recipients]):
            print("[ERROR] Email configuration incomplete")
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[{risk_level}] {subject}"
            
            body = f"""
Ransomware Alert Notification
Time: {datetime.now().isoformat()}
Risk Level: {risk_level}

{message}

This is an automated alert from the Ransomware Audit System.
"""
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender, password)
            server.send_message(msg)
            server.quit()
            
            print(f"[+] Email alert sent to {len(recipients)} recipient(s)")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
            return False
    
    def send_slack_alert(self, message, risk_level="MEDIUM"):
        if not self.slack_enabled:
            return False
        
        slack_config = self.config.get('slack', {})
        webhook_url = slack_config.get('webhook_url')
        
        if not webhook_url:
            print("[ERROR] Slack webhook URL not configured")
            return False
        
        color_map = {
            'LOW': '#36a64f',
            'MEDIUM': '#ff9900',
            'HIGH': '#ff6600',
            'CRITICAL': '#ff0000'
        }
        
        payload = {
            "attachments": [{
                "color": color_map.get(risk_level, '#808080'),
                "title": f"Ransomware Alert: {risk_level}",
                "text": message,
                "footer": "Ransomware Audit System",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                print("[+] Slack alert sent successfully")
                return True
            else:
                print(f"[ERROR] Slack returned status {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Failed to send Slack alert: {e}")
            return False
    
    def send_alert(self, subject, message, risk_level="MEDIUM"):
        success = []
        
        if self.email_enabled:
            if self.send_email_alert(subject, message, risk_level):
                success.append('email')
        
        if self.slack_enabled:
            if self.send_slack_alert(message, risk_level):
                success.append('slack')
        
        return success

def load_notification_config(config_file="notification_config.json"):
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"[ERROR] Failed to load config: {e}")
        return {}

def create_sample_config():
    sample = {
        "email": {
            "enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender": "your-email@gmail.com",
            "password": "your-app-password",
            "recipients": ["admin@company.com"]
        },
        "slack": {
            "enabled": False,
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        }
    }
    
    with open("notification_config.sample.json", 'w') as f:
        json.dump(sample, f, indent=2)
    
    print("[+] Sample config created: notification_config.sample.json")
    print("[*] Copy to notification_config.json and configure")
