import serial
import time
from datetime import datetime
import pandas as pd
from tabulate import tabulate
from colorama import init, Fore, Style
import re

init()

# Define color constants
class Colors:
    CYAN = Fore.CYAN + Style.BRIGHT    # Headers and banner
    GREEN = Fore.GREEN                 # Standard commands
    BLUE = Fore.BLUE                   # Kernel threads and known services
    RED = Fore.RED                     # Non-standard commands
    YELLOW = Fore.YELLOW               # Non-standard commands
    RESET = Style.RESET_ALL            # Reset to default

banner = """
      ____    ______   _____                  __ 
     /  _/___/_  __/  / ___/_________  __  __/ /_
     / // __ \\/ /     \\__ \\/ ___/ __ \\/ / / / __/
   _/ // /_/ / /     ___/ / /__/ /_/ / /_/ / /_  
  /___/\\____/_/     /____/\\___/\\____/\\__,_/\\__/  
                                             

Author: Darkma773r (https://github.com/darkmatter91)
"""


print(f"{Colors.CYAN}{banner}{Colors.RESET}")


# Standard commands as per FHS 3.0 (https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s04.html)
standard_commands = {
    # Required commands
    'cat', 'chgrp', 'chmod', 'chown', 'cp', 'date', 'dd', 'df', 'dmesg', 'echo',
    'false', 'kill', 'ln', 'login', 'ls', 'mkdir', 'mknod', 'more', 'mount', 'mv',
    'ps', 'pwd', 'rm', 'rmdir', 'sed', 'sh', 'stty', 'sync', 'true', 'umount', 'uname',
    # Optional commands
    'bash', 'csh', 'ed', 'tar', 'cpio', 'gzip', 'gunzip', 'zcat', 'netstat', 'ping', 'vi'
}


# Known services with descriptions (for process monitoring)
services_info = {
    "init": "Initial process",
    "dropbear": "Lightweight SSH server",
    "httpd": "HTTP server",
    "dhcpd": "DHCP server",
    "wlNetlinkTool": "Wireless network tool",
    "wscd": "Wi-Fi Simple Configuration daemon",
    "upnpd": "UPnP daemon",
    "afcd": "Apple Filing Protocol daemon",
    "dyndns": "Dynamic DNS client",
    "noipdns": "No-IP DNS client",
    "ntpc": "NTP client",
    "tmpd": "Temporary daemon",
    "dhcpc": "DHCP client",
    "tdpd": "Tunnel daemon",
    "cmxdns": "Custom DNS client",
    "dhcp6s": "DHCPv6 server",
    "cos": "Custom operation service",
    "dnsProxy": "DNS proxy",
    "igmpd": "IGMP daemon"
}


# Serial port settings (adjust port as needed)
port = "/dev/ttyUSB0"
try:
    serial_port = serial.Serial(
        port=port,
        baudrate=115200,
        bytesize=8,
        timeout=1,
        stopbits=serial.STOPBITS_ONE
    )
except serial.SerialException as e:
    print(f"{Colors.YELLOW}[!]Serial port error: {e}{Colors.RESET}")
    print(f"{Colors.YELLOW}[!]Ensure '{port}' is correct and accessible.{Colors.RESET}")
    exit(1)


def send_command(command):
    serial_port.write((command + '\r\n').encode())
    time.sleep(1)  
    output = ""
    while serial_port.in_waiting > 0:
        output += serial_port.read(serial_port.in_waiting).decode(errors='ignore')
        time.sleep(0.1)
    return output.strip()


def get_base_cmd(cmd):
    if cmd.startswith("[") and cmd.endswith("]"):
        return cmd[1:-1].split('/')[0]  # e.g., "mtdblock0" from "[mtdblock0]"
    cmd = cmd.strip().lstrip('<').strip()
    parts = cmd.split()
    return parts[0].split("/")[-1] if parts else ""


def classify_command(cmd, bin_commands, services_info):
    if cmd.startswith('[') and cmd.endswith(']'):
        base_cmd = get_base_cmd(cmd)
        return f"Kernel thread: {base_cmd}", Colors.BLUE
    base_cmd = get_base_cmd(cmd)
    if not re.match(r'^[a-zA-Z0-9_-]+$', base_cmd):
        return "Invalid command", Colors.YELLOW
    if base_cmd in standard_commands:
        return f"Standard Command: {base_cmd}", Colors.GREEN
    elif base_cmd in services_info:
        return services_info[base_cmd], Colors.BLUE
    else:
        return f"Non-Standard command: {base_cmd}", Colors.RED


# Main execution
print(f"{Colors.CYAN}[+] Waiting for device to boot (20 seconds)...{Colors.RESET}")
time.sleep(20)  # Give the device time to boot
print(f"{Colors.CYAN}[+] Device boot wait complete.{Colors.RESET}")


bin_output = send_command('ls /bin')
if not bin_output:
    print(f"{Colors.YELLOW}[!] Error: No output from 'ls /bin'. Check device connection or command.{Colors.RESET}")
    serial_port.close()
    exit(1)


bin_commands = set(cmd for cmd in bin_output.split() if re.match(r'^[a-zA-Z0-9_-]+$', cmd))


non_standard_bin = [cmd for cmd in bin_commands if cmd not in standard_commands]


timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
ps_output = send_command('ps')
lines = ps_output.splitlines()


data = []
for line in lines:
    process = line.strip()
    if process and process[0].isdigit():  
        fields = process.split()
        if len(fields) >= 5:
            pid = fields[0]
            user = fields[1]
            cmd = " ".join(fields[4:])
          
            description, color = classify_command(cmd, bin_commands, services_info)

            data.append([pid, user, f"{color}{cmd}{Colors.RESET}", f"{color}{description}{Colors.RESET}"])

if data:
    df = pd.DataFrame(data, columns=["PID", "USER", "CMD", "Description"])
    print(f"\n{Colors.CYAN}=== Process List (Timestamp: {timestamp}) ==={Colors.RESET}")
    print(tabulate(df, headers="keys", tablefmt="fancy_grid", showindex=False))
else:
    print(f"{Colors.YELLOW}[!] No valid process data collected.{Colors.RESET}")

print(f"\n{Colors.CYAN}[+] Enabled Commands in /bin:{Colors.RESET}")
menu_items = sorted(bin_commands)
for idx, cmd in enumerate(menu_items, 1):
    if cmd in standard_commands:
        print(f"{Colors.GREEN}{idx}. {cmd} (Standard Command){Colors.RESET}")
    else:
        print(f"{Colors.RED}{idx}. {cmd} (Non-Standard){Colors.RESET}")

while True:
    print(f"\n{Colors.CYAN}[+] Enter the number of the command to run (or 'q' to quit):{Colors.RESET}")
    choice = input("> ").strip().lower()

    if choice == 'q':
        print(f"{Colors.CYAN}Exiting...{Colors.RESET}")
        break

    try:
        choice_idx = int(choice) - 1
        if 0 <= choice_idx < len(menu_items):
            selected_cmd = menu_items[choice_idx]
            print(f"\n{Colors.CYAN}[+] Running command: {selected_cmd}{Colors.RESET}")
            output = send_command(selected_cmd)
            print(f"{Colors.CYAN}[+] Output:{Colors.RESET}")
            print(output if output else "No output received.")
        else:
            print(f"{Colors.YELLOW}[!] Invalid choice. Please select a number between 1 and {len(menu_items)}.{Colors.RESET}")
    except ValueError:
        print(f"{Colors.YELLOW}[!] Invalid input. Please enter a number or 'q' to quit.{Colors.RESET}")

# Clean up
serial_port.close()
