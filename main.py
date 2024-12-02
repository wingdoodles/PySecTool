import argparse
import tkinter as tk
from gui.main_window import MainWindow
from core.scanner import NetworkScanner
from core.cracker import PasswordCracker
from core.sniffer import PacketSniffer

def main():
    parser = argparse.ArgumentParser(description='PySecTool - Security Testing Suite')
    parser.add_argument('--gui', action='store_true', help='Launch GUI mode')
    parser.add_argument('--mode', choices=['scan', 'crack', 'sniff'], help='Operation mode')
    args = parser.parse_args()

    if args.gui:
        root = tk.Tk()
        app = MainWindow(root)
        root.mainloop()
    else:
        if args.mode == 'scan':
            scanner = NetworkScanner()
            scanner.start_scan()
        elif args.mode == 'crack':
            cracker = PasswordCracker()
            cracker.start_crack()
        elif args.mode == 'sniff':
            sniffer = PacketSniffer()
            sniffer.start_sniff()

if __name__ == '__main__':
    main()
