import jinja2
import pandas as pd
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.template_loader = jinja2.FileSystemLoader('templates')
        self.template_env = jinja2.Environment(loader=self.template_loader)

    def generate_report(self, title, findings):
        report = {
            'title': title,
            'findings': findings,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'metadata': {
                'total_findings': len(findings),
                'severity_levels': self._analyze_severity(findings),
                'categories': self._categorize_findings(findings)
            }
        }
        return report        
    def _analyze_severity(self, findings):
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            severity_counts[severity] += 1
        return severity_counts
        
    def _categorize_findings(self, findings):
        categories = {}
        for finding in findings:
            category = finding.get('category', 'general')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        return categories        