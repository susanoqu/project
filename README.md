# Personal Firewall with Tkinter GUI (Python)

A lightweight Python-based personal firewall with:

- Real-time packet sniffing using Scapy
- Customizable rule engine using JSON
- Live logging and monitoring
- Optional iptables blocking for system-level filtering
- Tkinter GUI for easy start/stop control
- Automatic network interface detection

This project is suitable for beginners learning cybersecurity, networking, or Python GUI development.

------------------------------------------------------------

## Features

### Firewall Engine
- Sniffs packets using Scapy AsyncSniffer
- Rule-based actions: allow, block, log
- Matches rules based on:
  - Protocol (TCP, UDP, ANY)
  - IP address (src/dst)
  - Port (src/dst)
  - Direction (inbound/outbound)

### Optional iptables Integration (Linux)
- Adds DROP rules automatically for blocked packets
- Can be enabled/disabled from the GUI

### Tkinter GUI
- Start/Stop firewall buttons
- Network interface selector (auto-detected)
- Reload rules
- Real-time log viewer window

### Logging
- All events saved in firewall.log
- GUI displays time-stamped logs

------------------------------------------------------------

## Project Structure

personal_firewall_gui.py        # Main firewall + GUI (single-file)
rules.json                      # Auto-created rule set
firewall.log                    # Log file
Personal_Firewall_GUI_Report.pdf  # Documentation (optional)

------------------------------------------------------------

## Installation

### 1. Install dependencies
Run the following commands on Linux:

sudo apt update

pip3 install scapy

sudo apt install python3-tk

### 3. Run the program (requires root)

sudo python3 personal_firewall_gui.py

------------------------------------------------------------

## How It Works

1. Scapy sniffs inbound and outbound packets.
2. Each packet is analyzed for:
   - Source IP
   - Destination IP
   - Ports
   - Protocol
   - Direction
3. Rules from rules.json are applied.
4. The first matching rule determines the action:
   - allow
   - block
   - log
5. Logs are displayed live in the GUI.

------------------------------------------------------------

## Tested On

- Kali Linux
- Ubuntu 22.04
- Debian
- Parrot OS

Note: Windows is not supported due to iptables and raw packet sniffing limitations.

------------------------------------------------------------

## Disclaimer

This project is for educational purposes only.
Do not use it on networks you do not own or manage.

