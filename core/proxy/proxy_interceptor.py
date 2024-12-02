import socket
import threading
import select
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import tempfile
import os
import time
import subprocess
import shutil
import dns.resolver
from pathlib import Path
from OpenSSL import crypto, SSL


class SSLCertGenerator:
    def __init__(self):
        self.ca_key = self._generate_key()
        self.ca_cert = self._generate_ca_cert(self.ca_key)
        self._save_ca_cert()
        self.cert_cache = {}

    def _generate_key(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)
        return key

    def _generate_ca_cert(self, key):
        cert = crypto.X509()
        cert.get_subject().CN = "PySecTool Root CA"
        cert.get_subject().O = "PySecTool Security"
        cert.get_subject().OU = "Security Testing"
        cert.get_subject().C = "US"
        cert.set_serial_number(int(time.time() * 1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])
        
        cert.sign(key, 'sha512')
        return cert

    def _save_ca_cert(self):
        with open('ca.crt', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca_cert))
        with open('ca.key', 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, self.ca_key))

    def generate_cert_for_host(self, hostname):
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        key = self._generate_key()
        cert = crypto.X509()
        cert.get_subject().CN = hostname
        cert.set_serial_number(int(time.time() * 1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(key)
        
        san_list = [f"DNS:{hostname}"]
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:FALSE"),
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
            crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode()),
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=self.ca_cert),
        ])
        
        cert.sign(self.ca_key, 'sha512')
        
        cert_path = f"certs/{hostname}.crt"
        key_path = f"certs/{hostname}.key"
        os.makedirs("certs", exist_ok=True)
        
        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        self.cert_cache[hostname] = (cert_path, key_path)
        return cert_path, key_path



class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        hostname, port = self.path.split(':')
        try:
            # Resolve DNS using Google's DNS
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            answers = resolver.resolve(hostname, 'A')
            ip_address = answers[0].address
            
            # Create connection using resolved IP
            remote_socket = socket.create_connection((ip_address, int(port)), timeout=10)
            
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            context = ssl.create_default_context()
            remote_ssl = context.wrap_socket(remote_socket, server_hostname=hostname)
            
            self._tunnel_https(self.connection, remote_ssl)
            
        except Exception as e:
            print(f"Connection details: {hostname}:{port}")
            print(f"Error: {e}")
            if not self.connection._closed:
                self.send_error(502)
            
    def _tunnel_https(self, client_socket, remote_socket):
        threads = []
        for (source, destination) in [(client_socket, remote_socket), (remote_socket, client_socket)]:
            thread = threading.Thread(
                target=self._transfer_data,
                args=(source, destination),
                daemon=True
            )
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
    def _transfer_data(self, source, destination):
        try:
            while True:
                data = source.recv(8192)
                if not data:
                    break
                destination.send(data)
        except:
            pass
        finally:
            try:
                source.close()
                destination.close()
            except:
                pass
    def do_GET(self):
        self._handle_request('GET')

    def do_POST(self):
        self._handle_request('POST')

    def _handle_request(self, method):
        url = self.path
        content_length = int(self.headers.get('Content-Length', 0))
        content = self.rfile.read(content_length) if content_length > 0 else b''
        
        request_data = {
            'method': method,
            'url': url,
            'headers': dict(self.headers),
            'content': content.decode('utf-8', 'ignore') if content else ''
        }
        
        if hasattr(self.server, 'proxy'):
            self.server.proxy.captured_requests.append(request_data)
            if self.server.proxy.callback:
                self.server.proxy.callback(request_data)

        try:
            self._forward_request(method, url, content)
        except Exception as e:
            self.send_error(502, f'Error handling request: {str(e)}')

    def _forward_request(self, method, url, content):
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        # Create remote connection
        remote_socket = socket.create_connection((hostname, port))
        
        if parsed_url.scheme == 'https':
            context = ssl.create_default_context()
            remote_socket = context.wrap_socket(remote_socket, server_hostname=hostname)
        
        # Construct request
        path = parsed_url.path or '/'
        if parsed_url.query:
            path += '?' + parsed_url.query
            
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {hostname}\r\n"
        
        # Forward original headers
        for header, value in self.headers.items():
            if header.lower() not in ('host', 'connection'):
                request += f"{header}: {value}\r\n"
        
        request += "Connection: close\r\n\r\n"
        
        # Send request and get response
        remote_socket.sendall(request.encode())
        
        # Stream response back to client
        while True:
            response = remote_socket.recv(8192)
            if not response:
                break
            self.wfile.write(response)
            
        remote_socket.close()        


class CertificateInstaller:
    def __init__(self):
        self.firefox_cert_dir = str(Path.home()) + "/.mozilla/firefox/"
        
    def install_cert_firefox(self, cert_path):
        profiles_dir = Path(self.firefox_cert_dir)
        profile_dirs = [d for d in profiles_dir.glob("*.default*") if d.is_dir()]
        
        for profile in profile_dirs:
            cert_db = profile / "cert9.db"
            if cert_db.exists():
                cmd = [
                    "certutil",
                    "-A",
                    "-n", "PySecTool Root CA",
                    "-t", "C,,",
                    "-i", cert_path,
                    "-d", f"sql:{profile}"
                ]
                try:
                    subprocess.run(cmd, check=True)
                    print(f"Certificate installed in Firefox profile: {profile}")
                except subprocess.CalledProcessError:
                    print(f"Certificate installation failed for profile: {profile}")

class ProxyInterceptor:
    def __init__(self):
        self.intercept_rules = []
        self.captured_requests = []
        self.is_running = False
        self.port = 8080
        self.callback = None
        self.server = None
        self.cert_generator = SSLCertGenerator()
        self.cert_installer = CertificateInstaller()

    def start_proxy(self):
        if not self.is_running:
            self.is_running = True
            self.server = HTTPServer(('127.0.0.1', self.port), ProxyHandler)
            self.server.cert_generator = self.cert_generator
            self.server.proxy = self
            
            # Start in a new thread
            proxy_thread = threading.Thread(target=self._run_server)
            proxy_thread.daemon = True
            proxy_thread.start()
            
            print(f"Proxy server running on http://127.0.0.1:{self.port}")
            
    def _run_server(self):
        while self.is_running:
            try:
                self.server.serve_forever()
            except Exception as e:
                print(f"Server thread: {e}")
                break            

    def stop_proxy(self):
        if self.is_running:
            self.is_running = False
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                print("Proxy server stopped")

    def log_request(self, request_data):
        self.captured_requests.append(request_data)
        if self.callback:
            self.callback(request_data)

    def add_rule(self, rule_type, match, action, value, header=None):
        rule = {
            'type': rule_type,
            'match': match,
            'action': action,
            'value': value,
            'header': header,
            'active': True
        }
        self.intercept_rules.append(rule)

    def save_captured_requests(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.captured_requests, f, indent=4)


