import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class SocialEngineeringToolkit:
    def __init__(self):
        self.smtp_config = {
            'server': 'localhost',
            'port': 1025,  # Debug server port
            'username': None,
            'password': None
        }
        self.templates = self.load_templates()
    
    def get_templates(self):
        return list(self.templates.keys())
        
    def load_templates(self):
        return {
            'password_reset': 'templates/password_reset.html',
            'account_verify': 'templates/account_verify.html',
            'urgent_login': 'templates/urgent_login.html'
        }
        
    def create_campaign(self, name, template, targets):
        return {
            'name': name,
            'template': template,
            'targets': targets,
            'subject': f"Security Alert: {name}",  # Default subject
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    def launch_campaign(self, campaign):
        results = []
        for target in campaign['targets']:
            result = self.send_phishing_email(target, campaign)
            results.append(result)
        return results
    
    def send_phishing_email(self, target, campaign):
        msg = MIMEMultipart()
        msg['From'] = "security.research@pentesting.local"
        msg['To'] = target
        msg['Subject'] = campaign['subject']
        
        body = self.templates[campaign['template']]
        msg.attach(MIMEText(body, 'html'))
        
        try:
            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'])
            server.starttls()  # Enable TLS for security
            if self.smtp_config['username']:
                server.login(self.smtp_config['username'], self.smtp_config['password'])
            server.send_message(msg)
            server.quit()
            
            return {
                'target': target,
                'status': 'success',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return {
                'target': target,
                'status': f'delivery_status: {str(e)}',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }