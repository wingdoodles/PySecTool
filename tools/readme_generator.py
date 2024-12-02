import json

readme_data = {
    "title": "PySecTool - Advanced Security Testing Framework 🛡️",
    "description": "PySecTool is a comprehensive security testing framework that combines multiple powerful tools into one unified interface.",
    "features": [
        "Network Scanner: Advanced port scanning and service detection",
        "Password Cracker: Multi-algorithm hash cracking capabilities",
        "Packet Sniffer: Real-time network traffic analysis",
        "Vulnerability Scanner: Automated security assessment",
        "Web Proxy: HTTP/HTTPS traffic interception",
        "Social Engineering: Campaign management and tracking",
        "Exploit Framework: Modular exploit development",
        "Forensics Analysis: Memory and disk analysis tools",
        "Report Generator: Professional security reports"
    ],
    "installation": {
        "steps": [
            "git clone https://github.com/wingdoodles/PySecTool.git",
            "cd PySecTool",
            "python3 install_requirements.py"
        ]
    },
    "usage": {
        "gui": "sudo python3 main.py --gui",
        "modules": [
            "python3 main.py --scan <target>",
            "python3 main.py --sniff <interface>",
            "python3 main.py --crack <hashfile>"
        ]
    },
    "requirements": [
        "Python 3.8+",
        "Root/Administrator privileges for certain features",
        "Network access for scanning functions"
    ],
    "contributing": [
        "Fork the repository",
        "Create your feature branch",
        "Commit your changes",
        "Push to the branch",
        "Create a Pull Request"
    ],
    "license": "MIT",
    "disclaimer": "This tool is for educational and professional security testing only. Users are responsible for complying with applicable laws and regulations.",
    "contact": {
        "website": "Hardrivetech.net",
        "email": "thardisky@hardrivetech.net"
    },
    "acknowledgments": [
        "Thanks to all contributors",
        "Inspired by industry-standard security tools",
        "Built with Python and modern security testing principles"
    ]
}

# Save as JSON
with open('readme_template.json', 'w') as f:
    json.dump(readme_data, f, indent=2)
