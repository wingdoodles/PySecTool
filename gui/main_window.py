import tkinter as tk
from tkinter import ttk
import threading
import json
import netifaces
from tkinter import filedialog
from tkinter import messagebox
from core.exploit.framework import ExploitFramework
from core.forensics.analyzer import ForensicsAnalyzer
from core.report.generator import ReportGenerator
from core.scanner import NetworkScanner
from core.cracker import PasswordCracker
from core.sniffer import PacketSniffer
from core.vulnerability_scanner import VulnerabilityScanner
from core.proxy.proxy_interceptor import ProxyInterceptor
from core.social.toolkit import SocialEngineeringToolkit

class MainWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("PySecTool")
        self.master.geometry("1024x768")
        
        # Create Menu Bar
        self.menu_bar = tk.Menu(self.master)
        self.master.config(menu=self.menu_bar)
        
        # File Menu
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Configuration", command=self.save_config)
        file_menu.add_command(label="Load Configuration", command=self.load_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        
        # Tools Menu
        tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Settings", command=self.show_settings)
        tools_menu.add_command(label="Reset All", command=self.reset_all)
        
        # Help Menu
        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Main container
        self.main_container = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Left side tabs using Treeview
        self.tree = ttk.Treeview(self.main_container, show='tree')
        self.main_container.add(self.tree, weight=1)
        
        # Right side content frame
        self.content_frame = ttk.Frame(self.main_container)
        self.main_container.add(self.content_frame, weight=4)
        
        # Add tabs to treeview
        self.tabs = {
            'Network Scanner': ScanTab(self.content_frame),
            'Password Cracker': CrackTab(self.content_frame),
            'Packet Sniffer': SniffTab(self.content_frame),
            'Vulnerability Scanner': VulnTab(self.content_frame),
            'Web Proxy': ProxyTab(self.content_frame),
            'Social Engineering': SocialTab(self.content_frame),
            'Exploit Framework': ExploitTab(self.content_frame),
            'Forensics Analysis': ForensicsTab(self.content_frame),
            'Report Generator': ReportTab(self.content_frame)
        }
        
        for name in self.tabs:
            self.tree.insert('', 'end', text=name, tags=(name,))
        
        # Bind tree selection
        self.tree.bind('<<TreeviewSelect>>', self.show_tab)
        
        # Show first tab by default
        first_tab = next(iter(self.tabs.values()))
        first_tab.pack(fill=tk.BOTH, expand=True)
        
    def show_tab(self, event):
        selected = self.tree.selection()[0]
        tab_name = self.tree.item(selected)['text']
        
        # Hide all tabs
        for tab in self.tabs.values():
            tab.pack_forget()
            
        # Show selected tab
        self.tabs[tab_name].pack(fill=tk.BOTH, expand=True)

    def show_documentation(self):
        doc_window = tk.Toplevel(self.master)
        doc_window.title("PySecTool Documentation")
        doc_window.geometry("1024x768")
        
        main_frame = ttk.PanedWindow(doc_window, orient=tk.HORIZONTAL)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        nav_frame = ttk.Frame(main_frame)
        main_frame.add(nav_frame, weight=1)
        
        content_frame = ttk.Frame(main_frame)
        main_frame.add(content_frame, weight=3)
        
        nav_tree = ttk.Treeview(nav_frame, show='tree')
        nav_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        content_text = tk.Text(content_frame, wrap=tk.WORD, padx=10, pady=10)
        scrollbar = ttk.Scrollbar(content_frame, command=content_text.yview)
        content_text.configure(yscrollcommand=scrollbar.set)
        
        content_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
        # Documentation sections
        docs = {
            'Getting Started': {
                'Installation': 'Step-by-step installation guide...',
                'Quick Start': 'Basic usage instructions...',
                'Configuration': 'Initial setup and configuration...'
            },
            'Tools': {
                'Network Scanner': '''
                Network Scanner Module
                
                Features:
                • Host Discovery
                • Port Scanning
                • Service Detection
                • Network Mapping
                
                Usage:
                1. Enter target IP/range
                2. Select scan type
                3. Configure options
                4. Start scan
                
                Advanced Features:
                • Custom port ranges
                • Protocol selection
                • Timing controls
                • Output formats
                ''',
                'Password Cracker': '''
                Password Cracker Module
                
                Features:
                • Multiple hash formats
                • Dictionary attacks
                • Brute force
                • Rainbow tables
                
                Supported Formats:
                • MD5
                • SHA1/256/512
                • NTLM
                • BCrypt
                ''',
                'Packet Sniffer': '''
                Packet Sniffer Module
                
                Features:
                • Live capture
                • Protocol analysis
                • Filter options
                • Traffic statistics
                
                Supported Protocols:
                • TCP/IP
                • HTTP/HTTPS
                • DNS
                • SMTP
                ''',
                'Web Proxy': '''
                Web Proxy Module
                
                Features:
                • HTTP/HTTPS interception
                • Request/Response modification
                • SSL certificate generation
                • Traffic logging
                
                Advanced Features:
                • Custom rules
                • Match/Replace
                • Script injection
                • Authentication handling
                '''
            },
            'Advanced Topics': {
                'Custom Scripts': 'Creating custom scripts...',
                'API Integration': 'API documentation...',
                'Best Practices': 'Security testing guidelines...'
            }
        }
        
        def show_content(event):
            selection = nav_tree.selection()[0]
            item = nav_tree.item(selection)
            parent_id = nav_tree.parent(selection)
            
            if parent_id:  # This is a subsection
                section = nav_tree.item(parent_id)['text']
                subsection = item['text']
                if section in docs and subsection in docs[section]:
                    content_text.config(state='normal')
                    content_text.delete(1.0, tk.END)
                    content_text.insert(tk.END, docs[section][subsection])
                    content_text.config(state='disabled')
    
        # Populate navigation tree
        for section, subsections in docs.items():
            section_id = nav_tree.insert('', 'end', text=section)
            for subsection in subsections:
                nav_tree.insert(section_id, 'end', text=subsection)
        
        nav_tree.bind('<<TreeviewSelect>>', show_content)
    
    def show_about(self):
        about_window = tk.Toplevel(self.master)
        about_window.title("About PySecTool")
        about_window.geometry("600x800")
        
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Helvetica", 24, "bold"))
        style.configure("Subtitle.TLabel", font=("Helvetica", 12))
        style.configure("Version.TLabel", font=("Helvetica", 10, "italic"))
        
        # Main container with padding
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and Logo
        ttk.Label(
            main_frame, 
            text="PySecTool", 
            style="Title.TLabel"
        ).pack(pady=(0,10))
        
        ttk.Label(
            main_frame,
            text="Professional Security Testing Suite",
            style="Subtitle.TLabel"
        ).pack()
        
        ttk.Label(
            main_frame,
            text="Version 1.0.0",
            style="Version.TLabel"
        ).pack(pady=(0,20))
        
        # Features Frame
        features_frame = ttk.LabelFrame(main_frame, text="Key Features", padding="10")
        features_frame.pack(fill=tk.X, pady=10)
        
        features = [
            "✓ Advanced Network Scanning",
            "✓ Vulnerability Assessment",
            "✓ Password Security Testing",
            "✓ Traffic Analysis",
            "✓ Web Application Testing",
            "✓ Social Engineering Tools",
            "✓ Exploit Framework",
            "✓ Forensics Analysis"
        ]
        
        for feature in features:
            ttk.Label(features_frame, text=feature).pack(anchor="w")
        
        # Credits
        credits_frame = ttk.Frame(main_frame)
        credits_frame.pack(fill=tk.X, pady=20)
        
        ttk.Label(
            credits_frame,
            text="Created by Security Professionals\nFor Security Professionals",
            justify=tk.CENTER
        ).pack()
        
        # Links
        links_frame = ttk.Frame(main_frame)
        links_frame.pack(fill=tk.X)
        
        ttk.Label(
            links_frame,
            text="Documentation • Support • License",
            foreground="blue",
            cursor="hand2"
        ).pack()
    def save_config(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json")
        if filename:
            config = self.get_current_config()
            with open(filename, 'w') as f:
                json.dump(config, f)
    
    def load_config(self):
        filename = filedialog.askopenfilename()
        if filename:
            with open(filename, 'r') as f:
                config = json.load(f)
            self.apply_config(config)
    
    def show_settings(self):
        settings_window = tk.Toplevel(self.master)
        settings_window.title("PySecTool Settings")
        settings_window.geometry("600x400")
        
        # Add settings controls here
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General Settings
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        # Network Settings
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="Network")
        
        # Security Settings
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security")
    
    def reset_all(self):
        if messagebox.askyesno("Reset All", "Are you sure you want to reset all settings?"):
            self.apply_default_config()

class ScanTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.scanner = NetworkScanner()
        self.init_ui()

    def init_ui(self):
        # Add scanning controls
        ttk.Label(self, text="Target IP/Range:").pack(pady=5)
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack(pady=5)
        ttk.Button(self, text="Start Scan", command=self.start_scan).pack(pady=5)
        self.result_text = tk.Text(self, height=10, width=50)
        self.result_text.pack(pady=5)

    def start_scan(self):
        self.scanner.target = self.target_entry.get()
        results = self.scanner.start_scan()
        self.result_text.delete(1.0, tk.END)
        for ip, mac in results:
            self.result_text.insert(tk.END, f"IP: {ip} - MAC: {mac}\n")

class CrackTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.cracker = PasswordCracker()
        self.init_ui()

    def init_ui(self):
        # Add password cracking controls
        ttk.Label(self, text="Target Hash:").pack(pady=5)
        self.hash_entry = ttk.Entry(self)
        self.hash_entry.pack(pady=5)
        ttk.Button(self, text="Start Cracking", command=self.start_crack).pack(pady=5)
        self.result_text = tk.Text(self, height=10, width=50)
        self.result_text.pack(pady=5)

    def start_crack(self):
        target_hash = self.hash_entry.get()
        result = self.cracker.start_crack(target_hash)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Result: {result}\n")

class SniffTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.sniffer = PacketSniffer()
        self.is_sniffing = False
        self.init_ui()

    def init_ui(self):
        # Interface selection
        ttk.Label(self, text="Interface:").pack(pady=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            self, 
            textvariable=self.interface_var,
            values=netifaces.interfaces()
        )
        self.interface_combo.pack(pady=5)
        
        # Control buttons frame
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)
        
        self.start_btn = ttk.Button(
            btn_frame, 
            text="Start Sniffing",
            command=self.start_sniffing
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop Sniffing",
            command=self.stop_sniffing,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display with scrollbar
        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = tk.Text(frame, height=20, width=70)
        scrollbar = ttk.Scrollbar(frame, command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def update_display(self, packet_info):
        self.result_text.insert(tk.END, f"{packet_info['timestamp']} - {packet_info['summary']}\n")
        self.result_text.see(tk.END)
        
    def start_sniffing(self):
        self.is_sniffing = True
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.interface_combo.configure(state=tk.DISABLED)
        
        def sniff_thread():
            while self.is_sniffing:
                self.sniffer.start_sniff(
                    interface=self.interface_var.get(),
                    count=1
                )
                if self.sniffer.captured_packets:
                    packet = self.sniffer.captured_packets[-1]
                    self.master.after(0, self.update_display, packet)
                    
        threading.Thread(target=sniff_thread, daemon=True).start()
        
    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.interface_combo.configure(state=tk.NORMAL)



class VulnTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.scanner = VulnerabilityScanner()
        self.init_ui()

    def init_ui(self):
        # Target URL input
        ttk.Label(self, text="Target URL:").pack(pady=5)
        self.url_entry = ttk.Entry(self, width=50)
        self.url_entry.pack(pady=5)

        # Scan options in a scrollable frame
        scan_container = ttk.LabelFrame(self, text="Vulnerability Checks")
        scan_container.pack(pady=10, padx=10, fill="x")

        # Create variables for all vulnerability types
        self.check_vars = {
            'xss': tk.BooleanVar(value=True),
            'sql': tk.BooleanVar(value=True),
            'lfi': tk.BooleanVar(value=True),
            'rce': tk.BooleanVar(value=True),
            'ssrf': tk.BooleanVar(value=True),
            'nosql': tk.BooleanVar(value=True)
        }

        # Create two columns of checkboxes
        left_frame = ttk.Frame(scan_container)
        right_frame = ttk.Frame(scan_container)
        left_frame.pack(side="left", padx=5, pady=5)
        right_frame.pack(side="left", padx=5, pady=5)

        # Add checkboxes in two columns
        checks = list(self.check_vars.items())
        mid_point = len(checks) // 2

        for i, (name, var) in enumerate(checks):
            frame = left_frame if i < mid_point else right_frame
            ttk.Checkbutton(
                frame, 
                text=name.upper(), 
                variable=var
            ).pack(anchor="w", pady=2)

        # Select/Deselect All buttons
        button_frame = ttk.Frame(scan_container)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(
            button_frame, 
            text="Select All", 
            command=self.select_all
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame, 
            text="Deselect All", 
            command=self.deselect_all
        ).pack(side="left", padx=5)

        # Progress indicators
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.progress_var).pack(pady=5)
        self.progress_bar = ttk.Progressbar(self, mode='indeterminate')
        self.progress_bar.pack(fill='x', padx=5, pady=5)

        # Start scan button
        ttk.Button(
            self, 
            text="Start Vulnerability Scan", 
            command=self.start_scan
        ).pack(pady=10)

        # Results area
        self.result_text = tk.Text(self, height=20, width=70)
        self.result_text.pack(pady=5, padx=5)

    def select_all(self):
        for var in self.check_vars.values():
            var.set(True)

    def deselect_all(self):
        for var in self.check_vars.values():
            var.set(False)

    def start_scan(self):
        url = self.url_entry.get()
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set("Scanning in progress...")
        self.progress_bar.start()
        
        # Get selected vulnerability types
        selected_vulns = [
            vuln_type for vuln_type, var in self.check_vars.items() 
            if var.get()
        ]
        
        def scan_thread():
            vulnerabilities = self.scanner.start_scan(url)
            self.master.after(0, self.update_results, vulnerabilities)
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def update_results(self, vulnerabilities):
        self.progress_bar.stop()
        self.progress_var.set("Scan complete")
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                self.result_text.insert(tk.END, 
                    f"Found {vuln['type']} vulnerability!\n"
                    f"URL: {vuln['url']}\n"
                    f"Parameter: {vuln['parameter']}\n"
                    f"Payload: {vuln['payload']}\n\n")
        else:
            self.result_text.insert(tk.END, "No vulnerabilities found.\n")

class ProxyTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.proxy = ProxyInterceptor()
        self.init_ui()

    def init_ui(self):
        # Proxy Control Frame
        control_frame = ttk.LabelFrame(self, text="Proxy Control")
        control_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(control_frame, text="Port:").pack(side="left", padx=5)
        self.port_entry = ttk.Entry(control_frame, width=6)
        self.port_entry.insert(0, "8080")
        self.port_entry.pack(side="left", padx=5)

        self.start_button = ttk.Button(
            control_frame, 
            text="Start Proxy", 
            command=self.toggle_proxy
        )
        self.start_button.pack(side="left", padx=5)

        # Rule Creation Frame
        rule_frame = ttk.LabelFrame(self, text="Interception Rules")
        rule_frame.pack(fill="x", padx=5, pady=5)

        # Rule Type
        ttk.Label(rule_frame, text="Type:").grid(row=0, column=0, padx=5, pady=5)
        self.rule_type = ttk.Combobox(
            rule_frame, 
            values=["request", "response"]
        )
        self.rule_type.grid(row=0, column=1, padx=5, pady=5)

        # Match URL
        ttk.Label(rule_frame, text="Match URL:").grid(row=1, column=0, padx=5, pady=5)
        self.match_entry = ttk.Entry(rule_frame)
        self.match_entry.grid(row=1, column=1, padx=5, pady=5)

        # Action
        ttk.Label(rule_frame, text="Action:").grid(row=2, column=0, padx=5, pady=5)
        self.action = ttk.Combobox(
            rule_frame, 
            values=["modify_header", "modify_content"]
        )
        self.action.grid(row=2, column=1, padx=5, pady=5)

        # Value
        ttk.Label(rule_frame, text="Value:").grid(row=3, column=0, padx=5, pady=5)
        self.value_entry = ttk.Entry(rule_frame)
        self.value_entry.grid(row=3, column=1, padx=5, pady=5)

        # Header (for modify_header action)
        ttk.Label(rule_frame, text="Header:").grid(row=4, column=0, padx=5, pady=5)
        self.header_entry = ttk.Entry(rule_frame)
        self.header_entry.grid(row=4, column=1, padx=5, pady=5)

        ttk.Button(
            rule_frame, 
            text="Add Rule", 
            command=self.add_rule
        ).grid(row=5, column=0, columnspan=2, pady=10)

        # Captured Traffic Display
        traffic_frame = ttk.LabelFrame(self, text="Captured Traffic")
        traffic_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.traffic_text = tk.Text(traffic_frame, height=15)
        self.traffic_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Export Button
        ttk.Button(
            self, 
            text="Export Captured Traffic", 
            command=self.export_traffic
        ).pack(pady=5)

    def toggle_proxy(self):
        if not self.proxy.is_running:
            self.proxy.port = int(self.port_entry.get())
            self.proxy.callback = self.update_traffic_display
            self.proxy.start_proxy()
            self.start_button.configure(text="Stop Proxy")
        else:
            self.proxy.stop_proxy()
            self.start_button.configure(text="Start Proxy")

    def add_rule(self):
        self.proxy.add_rule(
            self.rule_type.get(),
            self.match_entry.get(),
            self.action.get(),
            self.value_entry.get(),
            self.header_entry.get() if self.action.get() == "modify_header" else None
        )

    def update_traffic_display(self, request_data):
        self.traffic_text.insert(tk.END, 
            f"\n{request_data['method']} {request_data['url']}\n"
            f"Headers: {json.dumps(request_data['headers'], indent=2)}\n"
            f"Content: {request_data['content']}\n"
            f"{'='*50}\n"
        )
        self.traffic_text.see(tk.END)

    def export_traffic(self):
        filename = "captured_traffic.json"
        self.proxy.save_captured_requests(filename)
        self.traffic_text.insert(tk.END, f"\nTraffic exported to {filename}\n")

class SocialTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.toolkit = SocialEngineeringToolkit()
        
        # Campaign Configuration
        ttk.Label(self, text="Campaign Name:").pack(pady=5)
        self.campaign_entry = ttk.Entry(self)
        self.campaign_entry.pack(pady=5)
        
        # Template Selection
        ttk.Label(self, text="Email Template:").pack(pady=5)
        self.template_combo = ttk.Combobox(self, values=self.toolkit.get_templates())
        self.template_combo.pack(pady=5)
        
        # Target List
        ttk.Label(self, text="Target List:").pack(pady=5)
        self.target_text = tk.Text(self, height=5)
        self.target_text.pack(pady=5)
        
        ttk.Button(self, text="Launch Campaign", command=self.launch_campaign).pack(pady=10)
        
        # Results display
        self.results_text = tk.Text(self, height=10)
        self.results_text.pack(pady=5)
        
    def launch_campaign(self):
        campaign_name = self.campaign_entry.get()
        template = self.template_combo.get()
        targets = self.target_text.get("1.0", tk.END).splitlines()
        
        campaign = self.toolkit.create_campaign(
            name=campaign_name,
            template=template,
            targets=targets
        )
        
        results = self.toolkit.launch_campaign(campaign)
        self.display_results(results)
        
    def display_results(self, results):
        self.results_text.delete(1.0, tk.END)
        for result in results:
            self.results_text.insert(tk.END, 
                f"Target: {result['target']}\n"
                f"Status: {result['status']}\n"
                f"Time: {result['timestamp']}\n\n")


class ExploitTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.framework = ExploitFramework()
        
        # Exploit Selection
        ttk.Label(self, text="Available Exploits:").pack(pady=5)
        self.exploit_combo = ttk.Combobox(self, values=self.framework.get_exploits())
        self.exploit_combo.pack(pady=5)
        
        # Target Configuration
        ttk.Label(self, text="Target:").pack(pady=5)
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack(pady=5)
        
        ttk.Button(self, text="Run Exploit", command=self.run_exploit).pack(pady=10)
    def run_exploit(self):
        target = self.target_entry.get()
        exploit = self.exploit_combo.get()
        payload = self.payload_combo.get() if hasattr(self, 'payload_combo') else None
        result = self.framework.run_exploit(target, exploit, payload)
        self.show_result(result)

    def show_result(self, result):
        result_window = tk.Toplevel(self)
        result_window.title("Exploit Result")
        text = tk.Text(result_window, height=10, width=50)
        text.pack(padx=10, pady=10)
        text.insert(tk.END, f"Status: {result['status']}\nOutput: {result['output']}")


class ForensicsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.analyzer = ForensicsAnalyzer()
        
        # Memory Dump Selection
        ttk.Label(self, text="Memory Dump File:").pack(pady=5)
        self.dump_path = ttk.Entry(self)
        self.dump_path.pack(pady=5)
        ttk.Button(self, text="Browse", command=self.browse_dump).pack(pady=5)
        
        # Analysis Options
        self.options_frame = ttk.LabelFrame(self, text="Analysis Options")
        self.options_frame.pack(pady=10, fill="x")
        
        ttk.Button(self, text="Start Analysis", command=self.start_analysis).pack(pady=10)

    def browse_dump(self):
        filename = filedialog.askopenfilename()
        self.dump_path.delete(0, tk.END)
        self.dump_path.insert(0, filename)

    def start_analysis(self):
        dump_file = self.dump_path.get()
        results = self.analyzer.analyze_memory(dump_file)
        self.display_analysis(results)

    def display_analysis(self, results):
        analysis_window = tk.Toplevel(self)
        analysis_window.title("Analysis Results")
        text = tk.Text(analysis_window)
        text.pack(padx=10, pady=10)
        for result in results:
            text.insert(tk.END, f"{result}\n")


class ReportTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.generator = ReportGenerator()
        
        # Report Configuration
        ttk.Label(self, text="Report Title:").pack(pady=5)
        self.title_entry = ttk.Entry(self)
        self.title_entry.pack(pady=5)
        
        # Findings Selection
        self.findings_frame = ttk.LabelFrame(self, text="Include Findings")
        self.findings_frame.pack(pady=10, fill="x")
        
        ttk.Button(self, text="Generate Report", command=self.generate_report).pack(pady=10)

    def generate_report(self):
        title = self.title_entry.get()
        findings = self.collect_findings()
        report = self.generator.generate_report(title, findings)
        self.save_report(report)

    def collect_findings(self):
        findings = []
        # Collect findings from other tabs
        return findings

    def save_report(self, report):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)

