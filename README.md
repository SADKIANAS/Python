# Python
#!/usr/bin/env python3
"""
network_toolkit_installer.py

A bootstrap installer and cheat-sheet generator for a pro-focused networking toolkit.

Features:
- Install common networking, scanning, analysis, and monitoring tools (Debian/Ubuntu via apt).
- Generate a Markdown cheat-sheet with example commands for each category.
- Interactive mode to choose categories to install.
- Non-destructive: will attempt to install only requested packages and report failures.
- Shows ethical/legal reminder.

Usage:
    sudo ./network_toolkit_installer.py --install-all
    ./network_toolkit_installer.py --install "Discovery" "Packet"
    ./network_toolkit_installer.py --cheatsheet
    ./network_toolkit_installer.py --interactive

Notes:
- This script targets Debian/Ubuntu systems using apt. For other distributions, run the commands manually
  or adapt the package lists.
- Some tools (OpenVAS/GVM, ntopng, zabbix, metasploit) require additional post-install configuration and
  may not install cleanly from default repos; they are marked optional.
- Always have explicit authorization before scanning networks or hosts.
"""

import argparse
import os
import platform
import shlex
import subprocess
import sys
from datetime import datetime

# ---------- Configuration: categories and packages ----------
# Each entry: package_name (as in apt). Optional packages are prefixed with "(opt)" in the comment below.
CATEGORIES = {
    "Discovery & port scanning": {
        "packages": [
            "nmap",
            "arp-scan",
            "net-tools",
            "netcat-openbsd",
        ],
        "description": "Host discovery, port scanning, service detection (nmap, arp-scan, netcat).",
    },
    "Fast Internet-wide / mass scanning": {
        "packages": [
            "masscan",
            "zmap",  # may not be present in all Ubuntu repos; marked best-effort
        ],
        "description": "Mass/internet-scale scanners (masscan, zmap). Use responsibly.",
    },
    "Low-level packet & traffic analysis": {
        "packages": [
            "tcpdump",
            "wireshark-common",  # wireshark-qt/gtk has GUI; wireshark-common provides core data
            "tshark",
            "ngrep",
            "tcpflow",
            "python3-scapy",
        ],
        "description": "Packet capture and analysis (tcpdump, wireshark/tshark, scapy).",
    },
    "Service & protocol enumeration": {
        "packages": [
            "smbclient",
            "snmp",
            "snmp-mibs-downloader",  # may prompt during install for license; best-effort
            "nikto",
            "gobuster",
            "ldap-utils",
            "ncat",  # ncat from nmap
        ],
        "description": "SMB/SNMP/HTTP/LDAP enumeration tools.",
    },
    "Performance & stress testing": {
        "packages": [
            "iperf3",
            "hping3",
            "mtr-tiny",
        ],
        "description": "Throughput and path testing (iperf3, hping3, mtr).",
    },
    "Continuous monitoring / inventory / topology": {
        "packages": [
            "net-tools",
            # The following are optional / may need external repos or manual setup:
            "ntopng",      # optional, repo-specific in some distros
            "zabbix-agent",# optional
        ],
        "description": "Monitoring agents and inventory helpers. Some entries may require extra setup.",
    },
    "Vulnerability scanning & posture": {
        "packages": [
            "lynis",            # host auditing
            # The items below are heavy / require extra setup; best-effort:
            "openvas",          # may not exist as-is in all repos; in Debian it's GVM/OpenVAS packages
            "metasploit-framework",  # often not in default repos; optional
        ],
        "description": "Vulnerability scanners (lynis, OpenVAS/GVM, Metasploit — may need manual setup).",
    },
    "Automation & scripting": {
        "packages": [
            "python3",
            "python3-pip",
            "ansible",
        ],
        "description": "Automation/tooling: Python, pip, Ansible.",
    },
}

CHEATSHEET_PATH = "network_toolkit_cheatsheet.md"

# ---------- Helpers ----------

def is_root():
    return os.geteuid() == 0

def check_apt_available():
    try:
        subprocess.run(["apt-get", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False

def run_cmd(cmd, use_sudo=False, capture=False):
    if use_sudo and not is_root():
        cmd = ["sudo"] + cmd
    try:
        if capture:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            return (True, res.stdout.strip())
        else:
            subprocess.run(cmd, check=True)
            return (True, "")
    except subprocess.CalledProcessError as e:
        return (False, getattr(e, "stderr", "") or str(e))

def apt_update(use_sudo=True):
    print("[*] Running apt-get update ...")
    ok, msg = run_cmd(["apt-get", "update"], use_sudo=use_sudo)
    if not ok:
        print("[!] apt-get update failed:", msg)
    return ok

def install_packages(packages, use_sudo=True):
    results = {}
    for pkg in packages:
        print(f"[*] Installing {pkg} ...")
        ok, msg = run_cmd(["apt-get", "install", "-y", pkg], use_sudo=use_sudo)
        results[pkg] = {"ok": ok, "msg": msg}
        if not ok:
            print(f"[!] Failed to install {pkg}. See message below.")
            print(msg)
    return results

def generate_cheatsheet(path=CHEATSHEET_PATH):
    timestamp = datetime.utcnow().isoformat() + "Z"
    lines = []
    lines.append("# Network Toolkit Cheat-sheet")
    lines.append("")
    lines.append(f"Generated: {timestamp}")
    lines.append("")
    lines.append("> Ethical reminder: Only scan networks and hosts that you own or for which you have explicit authorization.")
    lines.append("")
    for cat, meta in CATEGORIES.items():
        lines.append(f"## {cat}")
        lines.append("")
        lines.append(meta.get("description", ""))
        lines.append("")
        pkgs = ", ".join(meta["packages"])
        lines.append(f"Packages (apt): {pkgs}")
        lines.append("")
        # Add example commands for prominent tools
        if "nmap" in meta["packages"] or cat.startswith("Discovery"):
            lines.append("Example commands:")
            lines.append("")
            lines.append("- Fast ping sweep: `sudo nmap -sn 192.168.1.0/24`")
            lines.append("- Full TCP SYN port scan: `sudo nmap -sS -p1-65535 -T4 target`")
            lines.append("- Service detection + scripts: `nmap -sV --script=vuln target`")
            lines.append("")
        if "masscan" in meta["packages"]:
            lines.append("- Masscan (fast internet-scale): `sudo masscan 203.0.113.0/24 -p80 --rate=10000 -oL results.txt`")
            lines.append("")
        if "tcpdump" in meta["packages"] or "tshark" in meta["packages"]:
            lines.append("- Capture HTTP traffic: `sudo tcpdump -i eth0 -w web.pcap port 80`")
            lines.append("- Read pcap with tshark: `tshark -r web.pcap -Y \"http.request\"`")
            lines.append("")
        if "iperf3" in meta["packages"]:
            lines.append("- iperf3 throughput test: server: `iperf3 -s` ; client: `iperf3 -c server-ip -P 10 -t 30`")
            lines.append("")
        if "hping3" in meta["packages"]:
            lines.append("- hping3 example (TTL or firewall testing): `sudo hping3 -S -p 80 --tcp-timestamp target`")
            lines.append("")
        if "snmp" in meta["packages"]:
            lines.append("- SNMP walk: `snmpwalk -v2c -c public 192.168.1.1`")
            lines.append("")
        if "lynis" in meta["packages"]:
            lines.append("- Lynis system audit: `sudo lynis audit system`")
            lines.append("")
        if "ansible" in meta["packages"]:
            lines.append("- Use Ansible to automate checks and installs across many hosts.")
            lines.append("")
    lines.append("## Quick recommended workflows")
    lines.append("")
    lines.append("- LAN inventory: `sudo arp-scan --localnet` -> `nmap -sS -p- -T4 -A hosts.txt`")
    lines.append("- Target enumeration: `nmap -sV --script default,safe -p- target` -> follow up with service-specific tools")
    lines.append("- Internet-scale research: `masscan` -> feed to `nmap` for service detection")
    lines.append("")
    lines.append("## Legal & safety")
    lines.append("")
    lines.append("- Always obtain written authorization before scanning networks you do not own.")
    lines.append("- Throttle mass scans (masscan `--rate`) to avoid disruption.")
    lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"[*] Cheat-sheet written to: {path}")
    return path

def interactive_menu():
    print("Interactive installer for Network Toolkit")
    print("----------------------------------------")
    print("Categories available:")
    names = list(CATEGORIES.keys())
    for i, name in enumerate(names, start=1):
        print(f"{i}) {name}")
    print("a) Install all")
    print("q) Quit")
    choice = input("Choose number (comma separated allowed), 'a' or 'q': ").strip()
    if choice.lower() == "q":
        print("Aborted.")
        return []
    if choice.lower() == "a":
        return names
    selected = []
    for token in choice.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            idx = int(token) - 1
            if 0 <= idx < len(names):
                selected.append(names[idx])
        except ValueError:
            print(f"Skipping invalid token: {token}")
    return selected

# ---------- Command-line ----------

def main():
    parser = argparse.ArgumentParser(
        description="Network Toolkit installer + cheat-sheet generator (Debian/Ubuntu apt)"
    )
    parser.add_argument("--install-all", action="store_true", help="Install all categories")
    parser.add_argument("--install", nargs="+", metavar="CATEGORY", help="Install one or more named categories (use quotes if name has spaces).")
    parser.add_argument("--cheatsheet", action="store_true", help="Generate cheat-sheet Markdown file only")
    parser.add_argument("--interactive", action="store_true", help="Run interactive menu to choose categories to install")
    parser.add_argument("--no-update", action="store_true", help="Skip running 'apt-get update' before installs")
    args = parser.parse_args()

    # Print header & legal notice
    print("Network Toolkit Installer")
    print("=========================")
    print("Ethical reminder: Only scan networks and hosts you own or have explicit authorization to test.")
    print("This script targets Debian/Ubuntu systems and uses apt for installation.")
    print("")

    distro = platform.system(), platform.release()
    if platform.system().lower() != "linux":
        print("[!] Warning: this script is designed for Linux (Debian/Ubuntu). Abort or adapt for your OS.")
    if not check_apt_available():
        print("[!] apt-get not found. This script requires apt. Abort.")
        sys.exit(2)

    use_sudo = not is_root()
    if use_sudo:
        print("[*] Not running as root: apt operations will use sudo when needed.")
    else:
        print("[*] Running as root.")

    to_install = []
    if args.install_all:
        to_install = list(CATEGORIES.keys())
    elif args.install:
        # Validate category names (allow partial matches case-insensitive)
        for user_cat in args.install:
            matched = None
            for cat in CATEGORIES.keys():
                if user_cat.lower() == cat.lower():
                    matched = cat
                    break
            if not matched:
                # try substring match
                choices = [cat for cat in CATEGORIES.keys() if user_cat.lower() in cat.lower()]
                if len(choices) == 1:
                    matched = choices[0]
                elif len(choices) > 1:
                    print(f"[!] Ambiguous category '{user_cat}', matches: {choices}. Skipping.")
                else:
                    print(f"[!] Unknown category '{user_cat}'. Skipping.")
            if matched:
                to_install.append(matched)
    elif args.interactive:
        chosen = interactive_menu()
        to_install = chosen
    elif args.cheatsheet:
        generate_cheatsheet()
        print("[*] Done.")
        return
    else:
        parser.print_help()
        return

    if not to_install:
        print("[*] No categories selected for installation. Exiting.")
        return

    print("[*] Selected categories for install:")
    for c in to_install:
        print(" -", c)
    print("")

    if not args.no_update:
        apt_update(use_sudo=use_sudo)

    # Aggregate packages (preserve order, avoid duplicates)
    pkgs = []
    seen = set()
    for cat in to_install:
        for p in CATEGORIES[cat]["packages"]:
            if p not in seen:
                pkgs.append(p)
                seen.add(p)

    print(f"[*] Will attempt to install {len(pkgs)} package(s).")
    print(", ".join(pkgs))
    print("")

    results = install_packages(pkgs, use_sudo=use_sudo)

    # Summary
    print("")
    print("Installation summary:")
    ok_count = sum(1 for r in results.values() if r["ok"])
    fail_count = len(results) - ok_count
    print(f"  Successful installs: {ok_count}")
    print(f"  Failed installs: {fail_count}")
    if fail_count:
        print("  Failed packages:")
        for pkg, info in results.items():
            if not info["ok"]:
                print("   -", pkg)
    print("")

    # Generate cheat-sheet
    generate_cheatsheet()

    print("[*] Completed. Review the cheat-sheet and adjust or re-run the script for additional packages.")
    print("Reminders:")
    print("- Some packages (e.g., openvas/gvm, ntopng, metasploit) may require manual post-install steps.")
    print("- For non-Debian systems, adapt package manager and package names accordingly.")
    print("")

if __name__ == "__main__":
    main()
