import subprocess
import sys

def install_requirements():
    requirements = [
        'scapy',
        'netifaces',
        'volatility3',
        'requests',
        'paramiko',
        'cryptography',
        'python-nmap',
        'pyOpenSSL',
        'beautifulsoup4',
        'pillow',
        'reportlab'
    ]
    
    print("Installing PySecTool dependencies...")
    for package in requirements:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    print("All dependencies installed successfully!")

if __name__ == "__main__":
    install_requirements()
