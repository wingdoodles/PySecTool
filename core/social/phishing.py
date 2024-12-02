import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class PhishingSimulator:
    def __init__(self):
        self.templates = self.load_templates()
        self.payloads = self.load_payloads()

    def create_campaign(self, target_list, template_name, payload):
        campaign = {
            'targets': target_list,
            'template': self.templates[template_name],
            'payload': self.payloads[payload]
        }
        return campaign
