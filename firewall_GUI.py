#!/usr/bin/env python3
"""
Personal Firewall with Tkinter GUI (Single File)

Requirements (Linux):
    sudo apt update
    sudo apt install python3-tk
    pip3 install scapy
"""

import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from threading import Lock

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# --- Scapy imports ---
try:
    from scapy.all import (
        AsyncSniffer,
        IP,
        TCP,
        UDP,
        conf,
        get_if_list,
    )
except Exception as e:
    print("[!] Error importing scapy. Install it with: pip3 install scapy")
    print(e)
    sys.exit(1)


LOG_FILE = "firewall.log"
RULES_FILE = "rules.json"


# -------------------- Logging Setup -------------------- #

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# -------------------- Rule Class -------------------- #

class Rule:
    def __init__(
        self,
        action,
        direction="any",
        src_ip="any",
        dst_ip="any",
        src_port="any",
        dst_port="any",
        protocol="any",
        description="",
    ):
        self.action = action.lower()        # allow, block, log
        self.direction = direction.lower()  # in, out, any
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper() if protocol != "any" else "any"
        self.description = description

    def matches(self, packet_info):
        """Check whether this rule matches the given packet info dict."""
        # Direction
        if self.direction != "any" and self.direction != packet_info["direction"]:
            return False

        # IPs
        if self.src_ip != "any" and self.src_ip != packet_info["src_ip"]:
            return False
        if self.dst_ip != "any" and self.dst_ip != packet_info["dst_ip"]:
            return False

        # Ports
        if self.src_port != "any" and self.src_port != packet_info["src_port"]:
            return False
        if self.dst_port != "any" and self.dst_port != packet_info["dst_port"]:
            return False

        # Protocol
        if self.protocol != "any" and self.protocol != packet_info["protocol"]:
            return False

        return True

    def __str__(self):
        return (
            f"<Rule action={self.action} dir={self.direction} proto={self.protocol} "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}>"
        )


# -------------------- Rule Loading -------------------- #

DEFAULT_RULESET = [
    {
        "action": "block",
        "direction": "in",
        "src_ip": "any",
        "dst_ip": "any",
        "src_port": "any",
        "dst_port": 23,
        "protocol": "TCP",
        "description": "Block inbound Telnet",
    },
    {
        "action": "log",
        "direction": "in",
        "src_ip": "any",
        "dst_ip": "any",
        "src_port": "any",
        "dst_port": 80,
        "protocol": "TCP",
        "description": "Log HTTP inbound",
    },
]


def ensure_default_rules():
    """Create a default rules.json if it does not exist."""
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w") as f:
            json.dump(DEFAULT_RULESET, f, indent=4)
        print(f"[+] Created default {RULES_FILE}")


def load_rules(path):
    rules = []
    if not os.path.exists(path):
        print(f"[!] Rules file {path} not found (creating default).")
        ensure_default_rules()

    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing {path}: {e}")
            return []

    for entry in data:
        rules.append(
            Rule(
                action=entry.get("action", "allow"),
                direction=entry.get("direction", "any"),
                src_ip=entry.get("src_ip", "any"),
                dst_ip=entry.get("dst_ip", "any"),
                src_port=entry.get("src_port", "any"),
                dst_port=entry.get("dst_port", "any"),
                protocol=entry.get("protocol", "any"),
                description=entry.get("description", ""),
            )
        )
    print(f"[+] Loaded {len(rules)} rules from {path}")
    return rules


# -------------------- Packet Parsing -------------------- #

def detect_default_interface():
    """Return first non-loopback interface, or None."""
    try:
        interfaces = get_if_list()
    except Exception:
        return None

    for iface in interfaces:
        if iface != "lo":
            return iface
    return None


def get_packet_info(pkt, local_ips):
    """Extract relevant info from scapy packet into a dict."""
    if IP not in pkt:
        return None  # Only IP packets

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    protocol = "OTHER"
    src_port = None
    dst_port = None

    if TCP in pkt:
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        protocol = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    # Direction: if source is local, it's outbound; if destination is local, inbound
    if src_ip in local_ips:
        direction = "out"
    elif dst_ip in local_ips:
        direction = "in"
    else:
        direction = "in"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "direction": direction,
    }


# -------------------- iptables Integration (Optional) -------------------- #

def apply_iptables_block(packet_info):
    """
    OPTIONAL: Add iptables rule to block destination IP and port.
    Requires root and iptables installed.
    """
    if packet_info["protocol"] not in ("TCP", "UDP"):
        return

    dst_ip = packet_info["dst_ip"]
    dst_port = packet_info["dst_port"]

    if dst_ip is None or dst_port is None:
        return

    chain = "INPUT" if packet_info["direction"] == "in" else "OUTPUT"

    cmd = [
        "iptables",
        "-A",
        chain,
        "-p",
        packet_info["protocol"].lower(),
        "-d",
        dst_ip,
        "--dport",
        str(dst_port),
        "-j",
        "DROP",
    ]
    try:
        subprocess.run(cmd, check=True)
        logging.info(f"Applied iptables rule: {' '.join(cmd)}")
    except Exception as e:
        logging.error(f"Failed to apply iptables rule: {e}")


# -------------------- Firewall Core -------------------- #

class Firewall:
    def __init__(self, rules, default_action="allow", use_iptables=False, gui_log_callback=None):
        self.rules = rules
        self.default_action = default_action.lower()
        self.use_iptables = use_iptables
        self.gui_log_callback = gui_log_callback
        self.log_lock = Lock()

        # Get local IPs
        self.local_ips = set()
        try:
            for route in conf.route.routes:
                if isinstance(route[4], str):
                    self.local_ips.add(route[4])
        except Exception:
            pass

    def _log_gui(self, msg, level="info"):
        with self.log_lock:
            if level == "info":
                logging.info(msg)
            elif level == "warn":
                logging.warning(msg)
            elif level == "error":
                logging.error(msg)

            if self.gui_log_callback:
                # Send to GUI in main thread via after()
                self.gui_log_callback(msg)

    def decide(self, packet_info):
        for rule in self.rules:
            if rule.matches(packet_info):
                return rule.action, rule
        return self.default_action, None

    def handle_packet(self, pkt):
        info = get_packet_info(pkt, self.local_ips)
        if info is None:
            return

        action, rule = self.decide(info)

        log_msg = (
            f"{action.upper()} {info['direction']} "
            f"{info['src_ip']}:{info['src_port']} -> "
            f"{info['dst_ip']}:{info['dst_port']} proto={info['protocol']} "
        )
        if rule and rule.description:
            log_msg += f"rule='{rule.description}'"

        if action == "allow":
            self._log_gui("[ALLOW] " + log_msg, "info")
        elif action == "block":
            self._log_gui("[BLOCK] " + log_msg, "warn")
            if self.use_iptables:
                apply_iptables_block(info)
        elif action == "log":
            self._log_gui("[LOG] " + log_msg, "info")
        else:
            self._log_gui("[UNKNOWN ACTION] " + log_msg, "error")


# -------------------- Tkinter GUI -------------------- #

class FirewallGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Python Personal Firewall")
        self.geometry("900x550")

        # Top frame: interface + iptables
        top_frame = tk.Frame(self)
        top_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Label(top_frame, text="Interface:").pack(side=tk.LEFT)

        self.iface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(top_frame, textvariable=self.iface_var, width=20)
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        self.use_iptables_var = tk.BooleanVar()
        self.iptables_check = tk.Checkbutton(
            top_frame, text="Use iptables for blocking", variable=self.use_iptables_var
        )
        self.iptables_check.pack(side=tk.LEFT, padx=10)

        # Buttons
        btn_frame = tk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_btn = tk.Button(btn_frame, text="Start Firewall", width=15, command=self.start_firewall)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(btn_frame, text="Stop Firewall", width=15, command=self.stop_firewall, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.reload_btn = tk.Button(btn_frame, text="Reload Rules", width=15, command=self.reload_rules)
        self.reload_btn.pack(side=tk.LEFT, padx=5)

        # Log area
        self.log_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status bar
        self.status_var = tk.StringVar(value="Idle")
        status_bar = tk.Label(self, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Firewall / sniffer
        self.firewall = None
        self.sniffer = None

        # Populate interfaces
        self.populate_interfaces()

        # Ensure rules file exists
        ensure_default_rules()

        # Close handler
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Warn if not root
        try:
            if os.geteuid() != 0:
                self.append_log("[WARN] You are not running as root. Sniffing may not work.\n")
        except AttributeError:
            pass  # non-posix

    # ---------- GUI helpers ---------- #

    def populate_interfaces(self):
        try:
            interfaces = get_if_list()
        except Exception:
            interfaces = []

        self.interface_combo["values"] = interfaces

        default_iface = detect_default_interface()
        if default_iface and default_iface in interfaces:
            self.iface_var.set(default_iface)
        elif interfaces:
            self.iface_var.set(interfaces[0])

    def append_log(self, text):
        # Called from Firewall via callback, must be thread-safe
        def inner():
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_area.insert(tk.END, f"[{timestamp}] {text}\n")
            self.log_area.see(tk.END)

        # Make sure we run in Tk thread
        self.after(0, inner)

    # ---------- Button actions ---------- #

    def start_firewall(self):
        if self.sniffer is not None:
            messagebox.showinfo("Firewall", "Firewall is already running.")
            return

        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showerror("Error", "No network interface selected.")
            return

        rules = load_rules(RULES_FILE)
        if not rules:
            messagebox.showerror("Error", f"No valid rules found in {RULES_FILE}.")
            return

        self.firewall = Firewall(
            rules,
            default_action="allow",
            use_iptables=self.use_iptables_var.get(),
            gui_log_callback=self.append_log,
        )

        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                prn=self.firewall.handle_packet,
                store=False,
            )
            self.sniffer.start()
            self.append_log(f"[INFO] Firewall started on interface {iface}.")
            self.status_var.set(f"Running on {iface}")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.sniffer = None
            messagebox.showerror("Error", f"Failed to start sniffer on {iface}:\n{e}")
            self.append_log(f"[ERROR] Failed to start sniffer on {iface}: {e}")

    def stop_firewall(self):
        if self.sniffer is None:
            messagebox.showinfo("Firewall", "Firewall is not running.")
            return

        try:
            self.sniffer.stop()
            self.append_log("[INFO] Firewall stopped.")
        except Exception as e:
            self.append_log(f"[ERROR] Failed to stop sniffer: {e}")
        finally:
            self.sniffer = None
            self.firewall = None
            self.status_var.set("Idle")
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def reload_rules(self):
        try:
            rules = load_rules(RULES_FILE)
            if rules:
                self.append_log(f"[INFO] Rules reloaded from {RULES_FILE}.")
            else:
                self.append_log(f"[WARN] No rules loaded from {RULES_FILE}.")
        except Exception as e:
            self.append_log(f"[ERROR] Failed to reload rules: {e}")

    def on_close(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.destroy()


# -------------------- main -------------------- #

def main():
    app = FirewallGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
