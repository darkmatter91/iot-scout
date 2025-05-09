import serial
import time
import logging
from datetime import datetime
import pandas as pd
from tabulate import tabulate
from colorama import init, Fore, Style
import re
from typing import Dict, Set, List, Tuple, Optional
import os
import sys
import subprocess
import readline
import glob
import binwalk
import shutil
import tempfile
import importlib.util
import contextlib
import io

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@contextlib.contextmanager
def suppress_stderr():
    """Context manager to suppress stderr output."""
    stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = stderr

class Colors:
    """Color constants for terminal output."""
    CYAN = Fore.CYAN + Style.BRIGHT    # Headers and banner
    GREEN = Fore.GREEN                 # Standard commands
    BLUE = Fore.BLUE                   # Kernel threads and known services
    RED = Fore.RED                     # Non-standard commands
    YELLOW = Fore.YELLOW               # Warning messages
    RESET = Style.RESET_ALL            # Reset to default

class Config:
    """Configuration settings for the application."""
    SERIAL_PORT = "/dev/ttyUSB0"
    BAUD_RATE = 115200
    BYTE_SIZE = 8
    TIMEOUT = 1
    BOOT_WAIT_TIME = 20  # seconds
    COMMAND_DELAY = 1    # seconds
    READ_DELAY = 0.1     # seconds

def check_serial_port(port: str) -> bool:
    """Check if the serial port is available and not in use."""
    try:
        # Try to open the port
        test_serial = serial.Serial(port)
        test_serial.close()
        return True
    except serial.SerialException as e:
        if "Device or resource busy" in str(e):
            print(f"{Colors.YELLOW}[!] Serial port {port} is busy.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] This usually means another program is using the port.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Common programs that might be using the port:{Colors.RESET}")
            print(f"{Colors.YELLOW}    - minicom{Colors.RESET}")
            print(f"{Colors.YELLOW}    - screen{Colors.RESET}")
            print(f"{Colors.YELLOW}    - Another instance of this program{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] To fix this, you can:{Colors.RESET}")
            print(f"{Colors.YELLOW}    1. Close any other programs using the port{Colors.RESET}")
            print(f"{Colors.YELLOW}    2. Run: sudo lsof {port}  (to see what's using the port){Colors.RESET}")
            print(f"{Colors.YELLOW}    3. Run: sudo fuser -k {port}  (to kill processes using the port){Colors.RESET}")
            print(f"{Colors.YELLOW}    4. If using screen: screen -X -S [session] quit{Colors.RESET}")
            print(f"{Colors.YELLOW}    5. If using minicom: minicom -D {port} -b 115200{Colors.RESET}")
            return False
        else:
            print(f"{Colors.RED}[!] Error checking serial port: {e}{Colors.RESET}")
            return False

class CommandClassifier:
    """Handles command classification and processing."""
    
    # Standard commands as per FHS 3.0 and common network utilities
    STANDARD_COMMANDS: Set[str] = {
        # Core system commands
        'ash', 'sh', 'bash', 'cat', 'chmod', 'chown', 'cp', 'date', 'dd', 'df',
        'dmesg', 'echo', 'kill', 'ln', 'login', 'ls', 'mkdir', 'mount', 'mv',
        'pidof', 'ping', 'ping6', 'ps', 'pwd', 'rm', 'rmdir', 'sed', 'sleep',
        'sync', 'umount', 'uname', 'nice', 'renice', 'ionice', 'chroot',
        'stty', 'true', 'false', 'yes', 'printf', 'env', 'printenv',
        
        # Process and system utilities
        'busybox', 'free', 'top', 'uptime', 'killall', 'reboot', 'poweroff',
        'halt', 'shutdown', 'init', 'sysctl', 'klogd', 'syslogd', 'logger',
        'watchdog', 'crond', 'crontab', 'at', 'atd', 'ntpd', 'hwclock',
        'date', 'time', 'usleep', 'sleep', 'iostat', 'mpstat', 'vmstat',
        'pgrep', 'pkill', 'pwdx', 'skill', 'tload', 'fuser', 'lsof',
        'pmap', 'pwck', 'vlock', 'chvt', 'deallocvt', 'dumpkmap', 'loadkmap',
        
        # Network core utilities
        'arp', 'arping', 'ifconfig', 'ip', 'route', 'netstat', 'ss',
        'nameif', 'ipcalc', 'netmsg', 'traceroute', 'tracepath', 'ping',
        'ping6', 'nslookup', 'dig', 'host', 'hostname', 'ifdown', 'ifup',
        'ifenslave', 'mii-tool', 'ethtool', 'tc', 'ip6tables', 'iptables',
        
        # Network services and daemons
        'dhcpd', 'dhcpc', 'dhclient', 'udhcpc', 'udhcpd', 'radvd', 'pppd',
        'pppoe', 'wpa_supplicant', 'hostapd', 'dnsmasq', 'ntpd', 'ntpc',
        'ntpdate', 'dropbear', 'dropbearkey', 'httpd', 'inetd', 'telnetd',
        'tftpd', 'ftpd', 'sshd', 'smbd', 'nmbd', 'rpcbind', 'portmap',
        
        # Network tools
        'wget', 'curl', 'tftp', 'ftp', 'sftp', 'scp', 'rsync', 'telnet',
        'ssh', 'nc', 'netcat', 'socat', 'tcpdump', 'nmap', 'mtr',
        'iperf', 'iperf3', 'speedtest', 'iptraf', 'nethogs', 'iftop',
        
        # Wireless tools
        'iwconfig', 'iwlist', 'iwpriv', 'iwspy', 'iwevent', 'iw',
        'wpa_cli', 'wpa_passphrase', 'iwgetid', 'rfkill', 'wlanconfig',
        
        # Router/IoT specific
        'wantype', 'wandetect', 'landetect', 'bridgedetect', 'vlanconfig',
        'switchconfig', 'ethphxcmd', 'mii_mgr', 'flash', 'mtd', 'nvram',
        'fw_printenv', 'fw_setenv', 'ubootenv', 'factorydefault', 'firstboot',
        'led', 'gpio', 'i2c', 'i2cdetect', 'i2cdump', 'i2cget', 'i2cset',
        
        # File utilities
        'touch', 'find', 'grep', 'egrep', 'fgrep', 'gzip', 'gunzip', 'tar',
        'unzip', 'vi', 'vim', 'nano', 'head', 'tail', 'more', 'less',
        'sort', 'uniq', 'wc', 'which', 'whereis', 'locate', 'xargs',
        'basename', 'dirname', 'realpath', 'readlink', 'md5sum', 'sha1sum',
        'sha256sum', 'sha512sum', 'sum', 'cksum', 'cmp', 'diff', 'patch',
        'split', 'csplit', 'cut', 'paste', 'join', 'tr', 'expand', 'unexpand',
        'fmt', 'pr', 'fold', 'head', 'tail', 'nl', 'od', 'hexdump', 'xxd',
        'strings', 'file', 'stat', 'truncate', 'shred', 'tee',
        
        # System configuration
        'passwd', 'adduser', 'deluser', 'chpasswd', 'useradd', 'userdel',
        'groupadd', 'groupdel', 'sudo', 'su', 'chage', 'last', 'lastlog',
        'who', 'w', 'whoami', 'groups', 'id', 'newgrp', 'sg', 'logname',
        'login', 'sulogin', 'vipw', 'vigr',
        
        # Storage and filesystem
        'fdisk', 'sfdisk', 'cfdisk', 'parted', 'mkfs', 'mke2fs', 'mkswap',
        'swapon', 'swapoff', 'fsck', 'e2fsck', 'tune2fs', 'resize2fs',
        'dumpe2fs', 'debugfs', 'blkid', 'findfs', 'lsblk', 'losetup',
        'mount', 'umount', 'mountpoint', 'df', 'du', 'sync', 'blockdev',
        
        # Memory management
        'free', 'slabtop', 'vmstat', 'pmap', 'smem', 'top', 'htop',
        
        # Hardware info
        'lspci', 'lsusb', 'lsscsi', 'dmidecode', 'hdparm', 'sdparm',
        'ethtool', 'mii-tool', 'setserial', 'hwclock', 'sensors',
        
        # Security
        'iptables', 'ip6tables', 'arptables', 'ebtables', 'ipset',
        'fail2ban-client', 'nft', 'tcpd', 'sudo', 'su', 'chroot',
        'ulimit', 'chmod', 'chown', 'chgrp', 'umask',
        
        # Package management (for systems that support it)
        'opkg', 'ipkg', 'dpkg', 'rpm', 'apt-get', 'yum', 'pacman',
        
        # Debug and diagnostics
        'strace', 'ltrace', 'gdb', 'valgrind', 'addr2line', 'size',
        'nm', 'objdump', 'readelf', 'ldd', 'ldconfig'
    }

    # Known services with descriptions
    SERVICES_INFO: Dict[str, str] = {
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

    # Vendor-specific commands that are likely custom
    VENDOR_SPECIFIC: Set[str] = {
        'afcd', 'ated_tp', 'cmxdns', 'cos', 'dnsProxy', 'dyndns', 'ebtables',
        'igmpd', 'ipping', 'ipcrm', 'ipcs', 'iwpriv', 'noipdns', 'ntpc',
        'pwdog', 'rt2860apd', 'taskset', 'tc', 'tddp', 'tdpd', 'tmpd', 'upnpd'
    }

    @staticmethod
    def get_base_cmd(cmd: str) -> str:
        """Extract the base command from a command string."""
        if cmd.startswith("[") and cmd.endswith("]"):
            return cmd[1:-1].split('/')[0]  # e.g., "mtdblock0" from "[mtdblock0]"
        cmd = cmd.strip().lstrip('<').strip()
        parts = cmd.split()
        return parts[0].split("/")[-1] if parts else ""

    @classmethod
    def classify_command(cls, cmd: str, bin_commands: Set[str]) -> Tuple[str, str]:
        """Classify a command and return its description and color."""
        if cmd.startswith('[') and cmd.endswith(']'):
            base_cmd = cls.get_base_cmd(cmd)
            return f"Kernel thread: {base_cmd}", Colors.BLUE
        
        base_cmd = cls.get_base_cmd(cmd)
        if not re.match(r'^[a-zA-Z0-9_-]+$', base_cmd):
            return "Invalid command", Colors.YELLOW
        
        if base_cmd in cls.STANDARD_COMMANDS:
            return f"Standard Linux Command: {base_cmd}", Colors.GREEN
        else:
            return f"Non-Standard (Vendor/Custom): {base_cmd}", Colors.RED

class SerialManager:
    """Manages serial communication with the device."""
    
    def __init__(self, port: str = Config.SERIAL_PORT, baud_rate: int = Config.BAUD_RATE):
        """Initialize serial connection."""
        self.port = port
        self.baud_rate = baud_rate
        self.serial_port = None
        self.connect()

    def connect(self) -> None:
        """Establish serial connection with error handling."""
        try:
            # Check if port is available
            if not check_serial_port(self.port):
                raise RuntimeError(f"Serial port {self.port} is not available")
                
            self.serial_port = serial.Serial(
                port=self.port,
                baudrate=self.baud_rate,
                bytesize=Config.BYTE_SIZE,
                timeout=Config.TIMEOUT,
                stopbits=serial.STOPBITS_ONE
            )
            logger.info(f"Successfully connected to {self.port}")
        except serial.SerialException as e:
            logger.error(f"Serial port error: {e}")
            print(f"{Colors.YELLOW}[!] Serial port error: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Ensure '{self.port}' is correct and accessible.{Colors.RESET}")
            raise

    def wait_for_boot(self) -> None:
        """Wait for the device to boot and be ready for commands."""
        print(f"{Colors.CYAN}[+] Waiting for device to boot ({Config.BOOT_WAIT_TIME} seconds)...{Colors.RESET}")
        time.sleep(Config.BOOT_WAIT_TIME)
        
        # Try to establish communication with the device
        max_retries = 5
        retry_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                # Send a simple command to check if device is responsive
                self.send_command('')
                # Try to get a response from ls /bin
                response = self.send_command('ls /bin')
                if response:
                    logger.info("Device is responsive and ready for commands")
                    print(f"{Colors.CYAN}[+] Device boot wait complete.{Colors.RESET}")
                    return
            except Exception as e:
                logger.warning(f"Boot check attempt {attempt + 1} failed: {e}")
            
            if attempt < max_retries - 1:
                print(f"{Colors.YELLOW}[!] Device not ready, waiting {retry_delay} seconds...{Colors.RESET}")
                time.sleep(retry_delay)
        
        raise RuntimeError("Device failed to become responsive after boot")

    def send_command(self, command: str) -> str:
        """Send a command to the device and return the response."""
        if not self.serial_port:
            raise RuntimeError("Serial port not initialized")
            
        self.serial_port.write((command + '\r\n').encode())
        time.sleep(Config.COMMAND_DELAY)
        
        output = ""
        while self.serial_port.in_waiting > 0:
            output += self.serial_port.read(self.serial_port.in_waiting).decode(errors='ignore')
            time.sleep(Config.READ_DELAY)
        return output.strip()

    def close(self) -> None:
        """Close the serial connection."""
        if self.serial_port:
            self.serial_port.close()
            logger.info("Serial connection closed")

    def search_sensitive_files(self) -> Tuple[Dict[str, Set[str]], Dict[str, Dict[str, List[str]]]]:
        """Search for sensitive files on the device via UART."""
        print(f"{Colors.CYAN}[+] Searching for sensitive files on the device...{Colors.RESET}")
        
        # Dictionary to store files by type
        files_by_type = {}
        pattern_matches = {}
        
        # First, search for critical system files with a more thorough approach
        critical_files = [
            'passwd',
            'shadow',
            'passwd.bak',
            'shadow.bak'
        ]
        
        # Common directories to search in
        common_dirs = [
            '/',
            '/etc',
            '/etc/config',
            '/etc/default',
            '/etc/init.d',
            '/etc/rc.d',
            '/bin',
            '/sbin',
            '/usr/bin',
            '/usr/sbin',
            '/var',
            '/var/etc',
            '/var/config',
            '/var/run',
            '/var/tmp',
            '/tmp',
            '/root',
            '/home',
            '/opt',
            '/mnt',
            '/media',
            '/proc',
            '/sys'
        ]
        
        # First try a direct search for the files
        for filename in critical_files:
            print(f"{Colors.CYAN}[+] Searching for {filename} files...{Colors.RESET}")
            # Use find command to locate files
            find_cmd = f"find / -name {filename} -type f 2>/dev/null"
            output = self.send_command(find_cmd)
            
            # Clean the output to remove command echo and shell prompts
            if output and output.strip():
                # Remove the command itself and any shell prompts from the output
                clean_output = output.replace(find_cmd, "")
                # Remove common shell prompts
                for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                    clean_output = clean_output.replace(prompt, "")
                clean_output = clean_output.strip()
                
                if clean_output:
                    for file_path in clean_output.splitlines():
                        if file_path.strip():
                            # Verify this is a file, not a directory or log message
                            ls_cmd = f"ls -l {file_path} 2>/dev/null"
                            ls_output = self.send_command(ls_cmd)
                            
                            # Clean the output
                            if ls_output and ls_output.strip():
                                clean_ls_output = ls_output
                                for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                                    clean_ls_output = clean_ls_output.replace(prompt, "")
                                clean_ls_output = clean_ls_output.strip()
                                
                                # Check if it's a regular file (not a directory or special file)
                                if clean_ls_output and "-rw" in clean_ls_output:
                                    file_type = self.get_file_type(file_path)
                                    if file_type not in files_by_type:
                                        files_by_type[file_type] = set()
                                    files_by_type[file_type].add(file_path)
                                    
                                    # Show contents for passwd and bak files
                                    if file_type in ['passwd', 'bak']:
                                        print(f"\n{Colors.YELLOW}[*] Found: {file_path}{Colors.RESET}")
                                        cat_cmd = f"cat {file_path}"
                                        cat_output = self.send_command(cat_cmd)
                                        # Clean the output to remove command echo and shell prompts
                                        if cat_output and cat_output.strip():
                                            clean_cat_output = cat_output.replace(cat_cmd, "")
                                            # Remove common shell prompts
                                            for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                                                clean_cat_output = clean_cat_output.replace(prompt, "")
                                            clean_cat_output = clean_cat_output.strip()
                                            
                                            if clean_cat_output:
                                                print(f"{Colors.YELLOW}[*] Contents:{Colors.RESET}")
                                                for line in clean_cat_output.splitlines():
                                                    if line.strip():
                                                        print(f"  {line.strip()}")
        
        # Search for configuration files that might contain sensitive information
        config_files = [
            'config',
            'conf',
            'cfg'
        ]
        
        for ext in config_files:
            print(f"{Colors.CYAN}[+] Searching for .{ext} files...{Colors.RESET}")
            find_cmd = f"find / -name '*.{ext}' -type f 2>/dev/null"
            output = self.send_command(find_cmd)
            
            # Clean the output to remove command echo and shell prompts
            if output and output.strip():
                clean_output = output.replace(find_cmd, "")
                # Remove common shell prompts
                for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                    clean_output = clean_output.replace(prompt, "")
                clean_output = clean_output.strip()
                
                if clean_output:
                    for file_path in clean_output.splitlines():
                        if file_path.strip():
                            # Verify this is a file, not a directory or log message
                            ls_cmd = f"ls -l {file_path} 2>/dev/null"
                            ls_output = self.send_command(ls_cmd)
                            
                            # Clean the output
                            if ls_output and ls_output.strip():
                                clean_ls_output = ls_output
                                for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                                    clean_ls_output = clean_ls_output.replace(prompt, "")
                                clean_ls_output = clean_ls_output.strip()
                                
                                # Check if it's a regular file
                                if clean_ls_output and "-rw" in clean_ls_output:
                                    file_type = ext
                                    if file_type not in files_by_type:
                                        files_by_type[file_type] = set()
                                    files_by_type[file_type].add(file_path)
        
        # Search for sensitive patterns in all files
        print(f"{Colors.CYAN}[+] Searching for sensitive patterns...{Colors.RESET}")
        for category, patterns in LocalFirmwareAnalyzer.SENSITIVE_PATTERNS.items():
            pattern_matches[category] = {}
            print(f"{Colors.YELLOW}[*] {category}:{Colors.RESET}")
            
            for pattern in patterns:
                # Use grep to search for patterns, but only in regular files
                # Add -h to suppress filenames and -n to show line numbers
                # Add -i for case-insensitive search and -m 3 to limit to 3 matches per file
                # Remove any -z option that might cause entire file output
                # Add --line-buffered to ensure line-by-line output
                grep_cmd = f"grep -r -h -n -i -m 3 --line-buffered '{pattern}' / --include='*.txt' --include='*.conf' --include='*.cfg' --include='*.config' 2>/dev/null"
                output = self.send_command(grep_cmd)
                
                # Clean the output to remove command echo and shell prompts
                if output and output.strip():
                    clean_output = output.replace(grep_cmd, "")
                    # Remove common shell prompts
                    for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                        clean_output = clean_output.replace(prompt, "")
                    clean_output = clean_output.strip()
                    
                    if clean_output:
                        # Process each line of output
                        for line in clean_output.splitlines():
                            if ':' in line:
                                # Split by the first colon to separate filename and line number
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    file_path, content = parts
                                    if file_path.strip():
                                        # Verify this is a file, not a directory or log message
                                        ls_cmd = f"ls -l {file_path} 2>/dev/null"
                                        ls_output = self.send_command(ls_cmd)
                                        
                                        # Clean the output
                                        if ls_output and ls_output.strip():
                                            clean_ls_output = ls_output
                                            for prompt in [">", "#", "$", "> ", "# ", "$ "]:
                                                clean_ls_output = clean_ls_output.replace(prompt, "")
                                            clean_ls_output = clean_ls_output.strip()
                                            
                                            # Check if it's a regular file
                                            if clean_ls_output and "-rw" in clean_ls_output:
                                                # Filter out JavaScript and large configuration files
                                                if not file_path.endswith('.js') and not file_path.endswith('.json'):
                                                    if file_path not in pattern_matches[category]:
                                                        pattern_matches[category][file_path] = []
                                                    
                                                    # Truncate content if it's too long (more than 100 chars)
                                                    if len(content) > 100:
                                                        content = content[:100] + "..."
                                                    
                                                    pattern_matches[category][file_path].append(content.strip())
            
            # Display matches for this category
            if pattern_matches[category]:
                for file_path, matches in pattern_matches[category].items():
                    print(f"{Colors.GREEN}{file_path}{Colors.RESET}")
                    # For files with many matches, just show the count instead of all matches
                    if len(matches) > 3:
                        print(f"  Found {len(matches)} matches")
                    else:
                        # Show up to 3 matches per file
                        for match in matches[:3]:
                            print(f"  {match}")
            else:
                print(f"{Colors.YELLOW}  Not Found{Colors.RESET}")
        
        # Ensure all file types are represented in the output, even if not found
        for file_type in ['passwd', 'shadow', 'bak', 'config', 'conf', 'cfg']:
            if file_type not in files_by_type:
                files_by_type[file_type] = set()
                print(f"{Colors.YELLOW}[*] {file_type} files: Not Found{Colors.RESET}")
        
        return files_by_type, pattern_matches
    
    @staticmethod
    def get_file_type(file_path: str) -> str:
        """Get the file type/extension."""
        ext = os.path.splitext(file_path)[1]
        if ext:
            return ext[1:]  # Remove the dot
        # Check for common file types without extensions
        if 'passwd' in file_path:
            return 'passwd'
        elif 'shadow' in file_path:
            return 'shadow'
        elif 'config' in file_path:
            return 'config'
        return 'unknown'

def check_dependencies() -> bool:
    """Check if all required dependencies are installed."""
    missing_deps = []
    
    # Check for binwalk
    try:
        import binwalk
    except ImportError:
        missing_deps.append("binwalk")
    
    # Check for jefferson
    try:
        import jefferson
    except ImportError:
        missing_deps.append("jefferson")
    
    if missing_deps:
        print(f"{Colors.RED}[!] Missing required dependencies: {', '.join(missing_deps)}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Please install them using: pip install {' '.join(missing_deps)}{Colors.RESET}")
        return False
    
    return True

class LocalFirmwareAnalyzer:
    """Analyzes local firmware files."""
    
    # Patterns to search for, categorized by type
    SENSITIVE_PATTERNS = {
        'Passwords': [
            r'password\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'root\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'admin\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'config\s*{\s*password\s*[\'"][^\'"]+[\'"]',
            r'wireless\s*{\s*key\s*[\'"][^\'"]+[\'"]'
        ],
        'API Keys': [
            r'api[_-]?key\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'apikey\s*[=:]\s*[\'"][^\'"]+[\'"]'
        ],
        'Secrets': [
            r'secret\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'private[_-]?key\s*[=:]\s*[\'"][^\'"]+[\'"]'
        ],
        'User Accounts': [
            r'root:.*:0:0:',
            r'admin:.*:0:0:',
            r'user\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'username\s*[=:]\s*[\'"][^\'"]+[\'"]',
            r'login\s*[=:]\s*[\'"][^\'"]+[\'"]'
        ]
    }
    
    # File extensions to exclude from pattern matching
    EXCLUDED_EXTENSIONS = [
        '.cpp', '.c', '.h', '.hpp', '.java', '.py', '.js', '.html', '.css', 
        '.xml', '.json', '.md', '.txt', '.log', '.sh', '.bat', '.ps1'
    ]
    
    # Keywords that indicate code comments or debug statements
    COMMENT_INDICATORS = [
        '//', '/*', '*/', '#', 'DEBUG', 'LOG', 'PRINT', 'ECHO', 'printf', 
        'console.log', 'System.out.println', 'cout <<', 'fprintf'
    ]
    
    def __init__(self, firmware_path: str):
        """Initialize firmware analyzer."""
        if not check_dependencies():
            raise RuntimeError("Missing required dependencies")
            
        self.firmware_path = firmware_path
        self.classifier = CommandClassifier()
        self.bin_directories = []
        self.extracted_path = None
        self.common_iot_binaries = [
            'busybox', 'dropbear', 'iptables', 'httpd', 'dhcpd', 'udhcpc', 'udhcpd',
            'dnsmasq', 'hostapd', 'wpa_supplicant', 'pppd', 'pppoe', 'pptp', 'l2tp',
            'xl2tpd', 'openvpn', 'ntpd', 'chronyd', 'syslogd', 'klogd', 'logd',
            'telnetd', 'ftpd', 'tftpd', 'sshd', 'vsftpd', 'proftpd', 'lighttpd',
            'nginx', 'boa', 'thttpd', 'mini_httpd', 'micro_httpd', 'goahead', 'uhttpd',
            'stunnel', 'openssl', 'openssh', 'dropbearkey', 'dropbearconvert',
            'dropbearmulti', 'busybox-suid'
        ]
        
        # Check if the input is a .bin file
        if self.firmware_path.endswith('.bin'):
            self.extract_firmware()
            
    def is_likely_code_or_comment(self, file_path: str, content: str) -> bool:
        """Check if a file is likely to be code or contains comments."""
        # Check file extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in self.EXCLUDED_EXTENSIONS:
            return True
            
        # Check for comment indicators
        for indicator in self.COMMENT_INDICATORS:
            if indicator in content:
                return True
                
        return False
    
    @staticmethod
    def try_read_file(file_path: str) -> Tuple[str, bool]:
        """Try to read a file with different encodings and methods."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                # Try different encodings
                for encoding in ['utf-8', 'latin-1', 'ascii']:
                    try:
                        return content.decode(encoding), True
                    except UnicodeDecodeError:
                        continue
                # If all decodings fail, return raw content
                return content.decode('latin-1', errors='replace'), True
        except Exception:
            return "", False
            
    def extract_firmware(self) -> None:
        """Extract firmware using binwalk."""
        print(f"{Colors.CYAN}[+] Extracting firmware using binwalk...{Colors.RESET}")
        
        # Create a temporary directory for extraction
        self.extracted_path = tempfile.mkdtemp(prefix='iot_scout_')
        
        try:
            # First, try to identify the filesystem type
            print(f"{Colors.CYAN}[+] Analyzing firmware structure...{Colors.RESET}")
            
            # Suppress all binwalk warnings
            logging.getLogger('binwalk').setLevel(logging.ERROR)
            logging.getLogger('binwalk.modules').setLevel(logging.ERROR)
            logging.getLogger('binwalk.modules.extractor').setLevel(logging.ERROR)
            
            with suppress_stderr():
                modules = binwalk.scan(self.firmware_path, signature=True, quiet=True)
            
            # Check if we have a JFFS2 filesystem
            has_jffs2 = False
            for module in modules:
                for result in module.results:
                    if 'jffs2' in result.description.lower():
                        has_jffs2 = True
                        break
                if has_jffs2:
                    break
            
            if has_jffs2:
                print(f"{Colors.CYAN}[+] Detected JFFS2 filesystem, using jefferson for extraction...{Colors.RESET}")
                try:
                    # Create jffs2-root directory
                    jffs2_dir = os.path.join(self.extracted_path, 'jffs2-root')
                    os.makedirs(jffs2_dir, exist_ok=True)
                    
                    # Use jefferson's command-line interface
                    import subprocess
                    with suppress_stderr():
                        result = subprocess.run(['jefferson', '-d', jffs2_dir, self.firmware_path], 
                                          capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        # Verify that files were actually extracted
                        if os.path.exists(jffs2_dir) and os.listdir(jffs2_dir):
                            self.firmware_path = jffs2_dir
                            print(f"{Colors.GREEN}[+] JFFS2 filesystem extracted to: {self.firmware_path}{Colors.RESET}")
                        else:
                            print(f"{Colors.YELLOW}[!] Jefferson completed but no files were extracted{Colors.RESET}")
                            has_jffs2 = False
                    else:
                        print(f"{Colors.YELLOW}[!] Error using jefferson: {result.stderr}{Colors.RESET}")
                        print(f"{Colors.YELLOW}[!] Falling back to binwalk extraction...{Colors.RESET}")
                        has_jffs2 = False
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error using jefferson: {e}{Colors.RESET}")
                    print(f"{Colors.YELLOW}[!] Falling back to binwalk extraction...{Colors.RESET}")
                    has_jffs2 = False
            
            if not has_jffs2:
                # Run binwalk extraction with warning suppression
                with suppress_stderr():
                    binwalk.scan(self.firmware_path, signature=True, extract=True, 
                                directory=self.extracted_path, quiet=True)
                
                # Find the extracted directory
                extracted_dirs = []
                for item in os.listdir(self.extracted_path):
                    item_path = os.path.join(self.extracted_path, item)
                    if os.path.isdir(item_path):
                        if item.endswith('.extracted') or item == 'jffs2-root':
                            # Verify directory is not empty
                            if os.listdir(item_path):
                                extracted_dirs.append(item)
                
                if extracted_dirs:
                    # If we have multiple extracted directories, prefer jffs2-root
                    if 'jffs2-root' in extracted_dirs:
                        self.firmware_path = os.path.join(self.extracted_path, 'jffs2-root')
                    else:
                        # Use the first extracted directory
                        self.firmware_path = os.path.join(self.extracted_path, extracted_dirs[0])
                    print(f"{Colors.GREEN}[+] Firmware extracted to: {self.firmware_path}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] No files were extracted. Using original firmware path.{Colors.RESET}")
                    self.firmware_path = os.path.dirname(self.firmware_path)  # Use the directory containing the firmware
            
            # Handle nested archives
            if os.path.exists(self.firmware_path):
                print(f"{Colors.CYAN}[+] Checking for nested archives...{Colors.RESET}")
                archive_patterns = ['*.tar', '*.gz', '*.zip', '*.bin']
                for pattern in archive_patterns:
                    for archive in glob.glob(os.path.join(self.firmware_path, pattern)):
                        print(f"{Colors.CYAN}[+] Found archive: {archive}{Colors.RESET}")
                        try:
                            # Extract nested archives to a subdirectory
                            archive_dir = os.path.join(self.firmware_path, 
                                os.path.splitext(os.path.basename(archive))[0])
                            os.makedirs(archive_dir, exist_ok=True)
                            with suppress_stderr():
                                binwalk.scan(archive, signature=True, extract=True,
                                          directory=archive_dir, quiet=True)
                        except Exception as e:
                            print(f"{Colors.YELLOW}[!] Error extracting nested archive {archive}: {e}{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error extracting firmware: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Using original firmware path.{Colors.RESET}")
            self.firmware_path = os.path.dirname(self.firmware_path)  # Use the directory containing the firmware
            
    def search_sensitive_files(self) -> Tuple[Dict[str, Set[str]], Dict[str, Dict[str, List[str]]]]:
        """Search for sensitive files and content in the firmware."""
        # Critical system files that we want to show contents for
        critical_files = {
            '/etc/passwd',
            '/etc/shadow',
            'etc/passwd',
            'etc/shadow'
        }
        
        # Other sensitive files to search for
        sensitive_files = [
            '/etc/config/passwd',
            '/etc/config/shadow',
            'config/passwd',
            'config/shadow',
            'etc/config/passwd',
            'etc/config/shadow',
            'config/passwd',
            'config/shadow'
        ]
        
        def get_file_type(file_path: str) -> str:
            """Get the file type/extension."""
            ext = os.path.splitext(file_path)[1]
            if ext:
                return ext[1:]  # Remove the dot
            # Check for common file types without extensions
            if 'passwd' in file_path:
                return 'passwd'
            elif 'shadow' in file_path:
                return 'shadow'
            elif 'config' in file_path:
                return 'config'
            return 'unknown'

        # Dictionary to store files by type
        files_by_type = {}

        # Search for critical and sensitive files
        for file_pattern in list(critical_files) + sensitive_files:
            for root, _, files in os.walk(self.firmware_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_pattern in file_path or file_pattern in os.path.join(root, file):
                        file_type = get_file_type(file_path)
                        if file_type not in files_by_type:
                            files_by_type[file_type] = set()  # Use set to avoid duplicates
                        files_by_type[file_type].add(file_path)

        # Display files by type
        print(f"\n{Colors.CYAN}[+] Found files by type:{Colors.RESET}")
        for file_type, files in sorted(files_by_type.items()):
            print(f"\n{Colors.YELLOW}[*] {file_type} files:{Colors.RESET}")
            for file_path in sorted(files):  # Convert set to sorted list
                print(f"{Colors.GREEN}{file_path}{Colors.RESET}")
                # Show contents for passwd and bak files
                if file_type in ['passwd', 'bak']:
                    content, success = self.try_read_file(file_path)
                    if success and content.strip():
                        for line in content.splitlines():
                            if line.strip():
                                print(f"  {line.strip()}")
        
        # Search for sensitive patterns - categorized by type
        print(f"\n{Colors.CYAN}[+] Files containing sensitive patterns:{Colors.RESET}")
        found_files = {}  # Dictionary to store all found files
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            print(f"\n{Colors.YELLOW}[*] {category}:{Colors.RESET}")
            category_files = {}  # Dictionary to store file paths and their matches
            for pattern in patterns:
                for root, _, files in os.walk(self.firmware_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        content, success = self.try_read_file(file_path)
                        if success:
                            # Skip files that are likely code or comments
                            if self.is_likely_code_or_comment(file_path, content):
                                continue
                                
                            try:
                                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                                if matches:
                                    if file_path not in category_files:
                                        category_files[file_path] = []
                                    for match in matches:
                                        line_start = max(0, content.rfind('\n', 0, match.start()) + 1)
                                        line_end = content.find('\n', match.end())
                                        if line_end == -1:
                                            line_end = len(content)
                                        context = content[line_start:line_end].strip()
                                        if context:
                                            category_files[file_path].append(context)
                            except Exception:
                                continue
            
            if category_files:
                found_files[category] = category_files
                for file_path, matches in sorted(category_files.items()):
                    print(f"{Colors.GREEN}{file_path}{Colors.RESET}")
                    # Show up to 3 matches per file
                    for match in matches[:3]:
                        print(f"  {match}")
                    if len(matches) > 3:
                        print(f"  ... and {len(matches) - 3} more matches")
            else:
                print(f"{Colors.YELLOW}  No files found{Colors.RESET}")
                
        return files_by_type, found_files

    def __del__(self):
        """Cleanup extracted files on object destruction."""
        if self.extracted_path and os.path.exists(self.extracted_path):
            try:
                shutil.rmtree(self.extracted_path)
            except Exception as e:
                logger.warning(f"Failed to cleanup extracted files: {e}")

    def find_bin_directories(self) -> List[str]:
        """Recursively find all bin directories in the firmware."""
        print(f"{Colors.CYAN}[+] Searching for bin directories...{Colors.RESET}")
        
        for root, dirs, files in os.walk(self.firmware_path):
            if 'bin' in dirs:
                bin_path = os.path.join(root, 'bin')
                self.bin_directories.append(bin_path)
                print(f"{Colors.GREEN}[+] Found bin directory: {bin_path}{Colors.RESET}")
        
        if not self.bin_directories:
            raise RuntimeError("No bin directories found in the firmware")
            
        return self.bin_directories
        
    def find_common_iot_binaries(self) -> Dict[str, List[str]]:
        """Find common IoT binaries in the firmware."""
        print(f"{Colors.CYAN}[+] Searching for common IoT binaries...{Colors.RESET}")
        
        results = {}
        for binary in self.common_iot_binaries:
            found_paths = []
            for root, _, files in os.walk(self.firmware_path):
                if binary in files:
                    found_paths.append(os.path.join(root, binary))
            
            if found_paths:
                results[binary] = found_paths
                print(f"{Colors.GREEN}[+] Found {binary} at: {', '.join(found_paths)}{Colors.RESET}")
        
        return results
        
    def analyze_bin_directories(self) -> Dict[str, List[str]]:
        """Analyze all found bin directories."""
        if not self.bin_directories:
            self.find_bin_directories()
            
        results = {}
        for bin_path in self.bin_directories:
            print(f"\n{Colors.CYAN}[+] Analyzing {bin_path}{Colors.RESET}")
            commands = []
            
            try:
                for item in os.listdir(bin_path):
                    item_path = os.path.join(bin_path, item)
                    if os.path.isfile(item_path):
                        commands.append(item)
                    elif os.path.isdir(item_path):
                        # Also check for executables in subdirectories
                        for root, _, files in os.walk(item_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                if os.path.isfile(file_path):
                                    # Get relative path from bin directory
                                    rel_path = os.path.relpath(file_path, bin_path)
                                    commands.append(rel_path)
                
                if commands:
                    results[bin_path] = sorted(commands)
                    print(f"{Colors.GREEN}[+] Found {len(commands)} items in {bin_path}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[!] No items found in {bin_path}{Colors.RESET}")
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error analyzing {bin_path}: {e}{Colors.RESET}")
                
        return results
        
    def display_analysis(self, bin_results: Dict[str, List[str]], iot_results: Dict[str, List[str]] = None) -> None:
        """Display the analysis results."""
        print(f"\n{Colors.CYAN}=== Firmware Analysis Results ==={Colors.RESET}")
        
        # Display bin directory contents
        for bin_path, commands in bin_results.items():
            print(f"\n{Colors.CYAN}[+] Contents of {bin_path}:{Colors.RESET}")
            print(f"{Colors.CYAN}[+] Found {len(commands)} items:{Colors.RESET}")
            
            for idx, cmd in enumerate(commands, 1):
                # Get the base command name for classification
                base_cmd = cmd.split('/')[-1]
                if base_cmd in self.classifier.STANDARD_COMMANDS:
                    print(f"{Colors.GREEN}{idx}. {cmd} (Standard Command){Colors.RESET}")
                else:
                    print(f"{Colors.RED}{idx}. {cmd} (Non-Standard){Colors.RESET}")
        
        # Display common IoT binaries found
        if iot_results:
            print(f"\n{Colors.CYAN}[+] Common IoT Binaries Found:{Colors.RESET}")
            for binary, paths in iot_results.items():
                print(f"{Colors.GREEN}[+] {binary}: {', '.join(paths)}{Colors.RESET}")

    def generate_report(self, bin_results: Dict[str, List[str]], iot_results: Dict[str, List[str]], 
                       files_by_type: Dict[str, Set[str]], pattern_matches: Dict[str, Dict[str, List[str]]]) -> None:
        """Generate a formatted report of the analysis results in Markdown format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"iot_scout_report_{timestamp}.md"
        
        with open(report_file, 'w') as f:
            # Write header
            f.write("# IoT Scout Analysis Report\n\n")
            f.write("---\n\n")
            f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Firmware Path:** `{self.firmware_path}`\n\n")
            
            # Write bin directory analysis
            f.write("## Binary Directory Analysis\n\n")
            for bin_path, commands in bin_results.items():
                f.write(f"### Directory: `{bin_path}`\n\n")
                f.write(f"Found {len(commands)} items:\n\n")
                f.write("```\n")
                for cmd in sorted(commands):
                    f.write(f"- {cmd}\n")
                f.write("```\n\n")
            
            # Write common IoT binaries
            f.write("## Common IoT Binaries\n\n")
            for binary, paths in iot_results.items():
                f.write(f"### {binary}\n\n")
                f.write("```\n")
                for path in paths:
                    f.write(f"- {path}\n")
                f.write("```\n\n")
            
            # Write files by type
            f.write("## Files by Type\n\n")
            for file_type, files in sorted(files_by_type.items()):
                f.write(f"### {file_type} files\n\n")
                if files:
                    for file_path in sorted(files):
                        f.write(f"- `{file_path}`\n")
                        # Show contents for passwd and bak files
                        if file_type in ['passwd', 'bak']:
                            content, success = self.try_read_file(file_path)
                            if success and content.strip():
                                f.write("\n```\n")
                                for line in content.splitlines():
                                    if line.strip():
                                        f.write(f"{line.strip()}\n")
                                f.write("```\n\n")
                else:
                    f.write("**Not Found**\n\n")
            
            # Write sensitive pattern matches
            f.write("## Sensitive Pattern Matches\n\n")
            for category, files in pattern_matches.items():
                f.write(f"### {category}\n\n")
                if files:
                    for file_path, matches in sorted(files.items()):
                        f.write(f"#### File: `{file_path}`\n\n")
                        f.write("```\n")
                        for match in matches:
                            f.write(f"- {match}\n")
                        f.write("```\n\n")
                else:
                    f.write(f"#### {category}\n\n")
                    f.write("**Not Found**\n\n")
            
            # Write footer
            f.write("---\n\n")
            f.write("Report generated by IoT Scout\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"\n{Colors.GREEN}[+] Report generated: {report_file}{Colors.RESET}")
        print(f"{Colors.CYAN}[+] The report is in Markdown format and can be viewed on GitHub or Obsidian{Colors.RESET}")
        
    def analyze_firmware(self) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """Analyze the firmware and return binary and IoT-specific results."""
        print(f"{Colors.CYAN}[+] Analyzing firmware: {self.firmware_path}{Colors.RESET}")
        
        # Find bin directories
        try:
            bin_dirs = self.find_bin_directories()
        except RuntimeError as e:
            print(f"{Colors.YELLOW}[!] {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Continuing with other analysis...{Colors.RESET}")
            bin_dirs = []
        
        # Analyze bin directories
        bin_results = {}
        if bin_dirs:
            bin_results = self.analyze_bin_directories()
        
        # Find common IoT binaries
        iot_results = self.find_common_iot_binaries()
        
        # Display analysis results
        self.display_analysis(bin_results, iot_results)
        
        return bin_results, iot_results

class ProcessMonitor:
    """Handles process monitoring and display."""
    
    def __init__(self, serial_manager: SerialManager):
        """Initialize process monitor."""
        self.serial_manager = serial_manager
        self.classifier = CommandClassifier()

    def get_process_list(self) -> List[List[str]]:
        """Get and format the process list."""
        ps_output = self.serial_manager.send_command('ps')
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
                    description, color = self.classifier.classify_command(cmd, set())
                    data.append([pid, user, cmd, description])
        return data

    def display_process_list(self) -> None:
        """Display the process list in a formatted table."""
        data = self.get_process_list()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if data:
            df = pd.DataFrame(data, columns=["PID", "USER", "CMD", "Description"])
            print(f"\n{Colors.CYAN}=== Process List (Timestamp: {timestamp}) ==={Colors.RESET}")
            print(tabulate(df, headers="keys", tablefmt="fancy_grid", showindex=False))
        else:
            print(f"{Colors.YELLOW}[!] No valid process data collected.{Colors.RESET}")
            
    def generate_process_report(self, data: List[List[str]], timestamp: str) -> str:
        """Generate a Markdown formatted process list for the report."""
        if not data:
            return "No process data available."
            
        report = "## Process List\n\n"
        report += f"**Timestamp:** {timestamp}\n\n"
        report += "| PID | USER | CMD | Description |\n"
        report += "|-----|------|-----|-------------|\n"
        
        for row in data:
            pid, user, cmd, desc = row
            # Escape any pipe characters in the data
            cmd = cmd.replace('|', '\\|')
            desc = desc.replace('|', '\\|')
            report += f"| {pid} | {user} | `{cmd}` | {desc} |\n"
            
        return report

class CommandMenu:
    """Handles command menu and execution."""
    
    def __init__(self, serial_manager: SerialManager):
        """Initialize command menu."""
        self.serial_manager = serial_manager
        self.classifier = CommandClassifier()
        self.menu_items = []
        self.initialize_menu()

    def initialize_menu(self) -> None:
        """Initialize the command menu."""
        bin_output = self.serial_manager.send_command('ls /bin')
        if not bin_output:
            logger.error("No output from 'ls /bin'")
            raise RuntimeError("Failed to get /bin contents")
        
        # Log the raw output for debugging
        logger.debug(f"Raw /bin output: {bin_output}")
        
        # Clean the output and extract valid commands
        clean_output = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', bin_output)
        
        # Split by whitespace and newlines, then filter out empty strings
        commands = []
        for line in clean_output.splitlines():
            # Split the line by whitespace and filter out empty strings
            line_commands = [cmd.strip() for cmd in line.split() if cmd.strip()]
            # Filter out directory names and invalid commands
            valid_commands = []
            for cmd in line_commands:
                # Skip if it's a directory name or path
                if cmd.startswith('/') or cmd == 'bin':
                    continue
                # Skip if it contains invalid characters
                if not re.match(r'^[a-zA-Z0-9_-]+$', cmd):
                    continue
                valid_commands.append(cmd)
            commands.extend(valid_commands)
        
        # Log the extracted commands
        logger.debug(f"Extracted commands: {commands}")
        
        if not commands:
            logger.error("No valid commands found in /bin")
            raise RuntimeError("No valid commands found in /bin")
        
        self.menu_items = sorted(set(commands))  # Remove duplicates and sort
        logger.info(f"Found {len(self.menu_items)} valid commands in /bin")

    def display_menu(self) -> None:
        """Display the command menu."""
        print(f"\n{Colors.CYAN}[+] Enabled Commands in /bin:{Colors.RESET}")
        for idx, cmd in enumerate(self.menu_items, 1):
            if cmd in self.classifier.STANDARD_COMMANDS:
                print(f"{Colors.GREEN}{idx}. {cmd} (Standard Command){Colors.RESET}")
            else:
                print(f"{Colors.RED}{idx}. {cmd} (Non-Standard){Colors.RESET}")

    def execute_command(self, choice: str) -> bool:
        """Execute the selected command."""
        if choice == 'q':
            return False

        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(self.menu_items):
                selected_cmd = self.menu_items[choice_idx]
                print(f"\n{Colors.CYAN}[+] Running command: {selected_cmd}{Colors.RESET}")
                output = self.serial_manager.send_command(selected_cmd)
                print(f"{Colors.CYAN}[+] Output:{Colors.RESET}")
                print(output if output else "No output received.")
            else:
                print(f"{Colors.YELLOW}[!] Invalid choice. Please select a number between 1 and {len(self.menu_items)}.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.YELLOW}[!] Invalid input. Please enter a number or 'q' to quit.{Colors.RESET}")
        
        return True

def display_banner():
    """Display the application banner."""
    # Define the banner without any indentation
    banner_lines = [
        "      ____    ______   _____                  __ ",
        "     /  _/___/_  __/  / ___/_________  __  __/ /_",
        "     / // __ \\/ /     \\__ \\/ ___/ __ \\/ / / / __/",
        "   _/ // /_/ / /     ___/ / /__/ /_/ / /_/ / /_  ",
        "  /___/\\____/_/     /____/\\___/\\____/\\__,_/\\__/  ",
        "                                             ",
        "",
        "Author: Darkma773r (https://github.com/darkmatter91)"
    ]
    
    # Calculate the width of the terminal
    terminal_width = 80
    
    # Center each line
    centered_banner = ""
    for line in banner_lines:
        # Calculate padding to center the line
        padding = (terminal_width - len(line)) // 2
        centered_banner += " " * padding + line + "\n"
    
    print(f"{Colors.CYAN}{centered_banner}{Colors.RESET}")

def display_startup_menu() -> int:
    """Display the startup menu and get user choice."""
    print(f"\n{Colors.CYAN}=== IoT Scout Startup Menu ==={Colors.RESET}")
    print(f"{Colors.CYAN}1. Capture live from UART{Colors.RESET}")
    print(f"{Colors.CYAN}2. Recon from local firmware{Colors.RESET}")
    print(f"{Colors.CYAN}3. Search for sensitive information{Colors.RESET}")
    
    while True:
        try:
            choice = int(input(f"\n{Colors.CYAN}Enter your choice (1-3): {Colors.RESET}"))
            if choice in [1, 2, 3]:
                return choice
            print(f"{Colors.YELLOW}[!] Invalid choice. Please enter 1, 2, or 3.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.YELLOW}[!] Invalid input. Please enter a number.{Colors.RESET}")

def complete_path(text: str, state: int) -> Optional[str]:
    """Tab completion function for file paths."""
    # Get the directory and base name
    if '/' in text:
        directory = os.path.dirname(text)
        base = os.path.basename(text)
    else:
        directory = '.'
        base = text
    
    # If directory doesn't exist, return None
    if not os.path.exists(directory):
        return None
    
    # Get all matching files/directories
    matches = []
    for path in glob.glob(os.path.join(directory, base + '*')):
        if os.path.isdir(path):
            matches.append(path + '/')
        else:
            matches.append(path)
    
    # Return the match at the current state
    try:
        return matches[state]
    except IndexError:
        return None

def get_firmware_path() -> str:
    """Get the path to the firmware directory with tab completion."""
    # Set up tab completion
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete_path)
    
    # Print instructions for tab completion
    print(f"{Colors.CYAN}[+] Tab completion is enabled. Press TAB to complete file paths.{Colors.RESET}")
    
    while True:
        try:
            path = input(f"\n{Colors.CYAN}Enter the path to the firmware directory: {Colors.RESET}")
            if os.path.exists(path):
                return path
            print(f"{Colors.YELLOW}[!] Path does not exist. Please enter a valid path.{Colors.RESET}")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

def main():
    """Main function to run the IoT Scout application."""
    try:
        # Initialize readline for tab completion
        try:
            import readline
            readline.parse_and_bind("tab: complete")
            print(f"{Colors.GREEN}[+] Tab completion enabled{Colors.RESET}")
        except ImportError:
            print(f"{Colors.YELLOW}[!] readline module not available. Tab completion will not work.{Colors.RESET}")
        
        # Initialize components
        serial_manager = None
        process_monitor = None
        command_menu = None
        analyzer = None
        files_by_type = {}
        pattern_matches = {}
        bin_results = {}
        iot_results = {}
        process_data = None
        
        # Display banner
        display_banner()
        
        # Display welcome message
        print(f"{Colors.CYAN}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.CYAN}{'IoT Scout - IoT Device Analysis Tool':^80}{Colors.RESET}")
        print(f"{Colors.CYAN}{'=' * 80}{Colors.RESET}")
        
        # Display menu
        while True:
            print(f"\n{Colors.CYAN}Menu Options:{Colors.RESET}")
            print(f"{Colors.YELLOW}1. Capture live from UART{Colors.RESET}")
            print(f"{Colors.YELLOW}2. Recon from local firmware{Colors.RESET}")
            print(f"{Colors.YELLOW}3. Search for sensitive information{Colors.RESET}")
            print(f"{Colors.YELLOW}4. Generate report{Colors.RESET}")
            print(f"{Colors.YELLOW}5. Exit{Colors.RESET}")
            
            choice = input(f"\n{Colors.CYAN}Enter your choice (1-5): {Colors.RESET}").strip()
            
            if choice == '1':
                # Option 1: Capture live from UART
                port = input(f"{Colors.CYAN}Enter UART port (e.g., /dev/ttyUSB0): {Colors.RESET}").strip()
                baud_rate = input(f"{Colors.CYAN}Enter baud rate (default: 115200): {Colors.RESET}").strip() or "115200"
                
                try:
                    serial_manager = SerialManager(port, int(baud_rate))
                    print(f"{Colors.GREEN}[+] Connected to {port} at {baud_rate} baud{Colors.RESET}")
                    
                    # Initialize process monitor and command menu with serial_manager
                    process_monitor = ProcessMonitor(serial_manager)
                    command_menu = CommandMenu(serial_manager)
                    
                    # Display process list
                    process_data = process_monitor.get_process_list()
                    process_monitor.display_process_list()
                    command_menu.display_menu()
                    
                    # Ask if user wants to search for sensitive information
                    while True:
                        search_choice = input(f"\n{Colors.CYAN}Would you like to search for sensitive information? (y/n): {Colors.RESET}").strip().lower()
                        if search_choice in ['y', 'n']:
                            break
                        print(f"{Colors.YELLOW}[!] Please enter 'y' or 'n'{Colors.RESET}")
                    
                    if search_choice == 'y':
                        # Search for sensitive files via UART
                        files_by_type, pattern_matches = serial_manager.search_sensitive_files()
                
                except Exception as e:
                    print(f"{Colors.RED}[!] Error connecting to UART: {e}{Colors.RESET}")
                    continue
            
            elif choice == '2':
                # Option 2: Recon from local firmware
                # Use tab completion for firmware path
                firmware_path = get_firmware_path()
                
                try:
                    analyzer = LocalFirmwareAnalyzer(firmware_path)
                    bin_results, iot_results = analyzer.analyze_firmware()
                    
                    # Ask if user wants to search for sensitive information
                    while True:
                        search_choice = input(f"\n{Colors.CYAN}Would you like to search for sensitive information? (y/n): {Colors.RESET}").strip().lower()
                        if search_choice in ['y', 'n']:
                            break
                        print(f"{Colors.YELLOW}[!] Please enter 'y' or 'n'{Colors.RESET}")
                    
                    if search_choice == 'y':
                        # Get files by type and pattern matches from search_sensitive_files
                        files_by_type, pattern_matches = analyzer.search_sensitive_files()
                
                except Exception as e:
                    print(f"{Colors.RED}[!] Error analyzing firmware: {e}{Colors.RESET}")
                    continue
            
            elif choice == '3':
                # Option 3: Search for sensitive information
                if serial_manager:
                    # Use UART connection if available
                    files_by_type, pattern_matches = serial_manager.search_sensitive_files()
                elif analyzer:
                    # Use firmware analyzer if available
                    files_by_type, pattern_matches = analyzer.search_sensitive_files()
                else:
                    print(f"{Colors.YELLOW}[!] No active connection or firmware loaded. Please select option 1 or 2 first.{Colors.RESET}")
                    continue
            
            elif choice == '4':
                # Option 4: Generate report
                if not (files_by_type or pattern_matches or bin_results or iot_results or process_data):
                    print(f"{Colors.YELLOW}[!] No data available for report generation. Please run an analysis first.{Colors.RESET}")
                    continue
                
                # Generate report
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_file = f"iot_scout_report_{timestamp}.md"
                
                with open(report_file, 'w') as f:
                    # Write header
                    f.write("# IoT Scout Analysis Report\n\n")
                    f.write("---\n\n")
                    
                    # Add timestamp
                    f.write(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Add process list if available
                    if process_data:
                        f.write("## Process List\n\n")
                        f.write("| PID | USER | CMD | Description |\n")
                        f.write("|-----|------|-----|-------------|\n")
                        for proc in process_data:
                            f.write(f"| {proc['pid']} | {proc['user']} | {proc['cmd']} | {proc['description']} |\n")
                        f.write("\n---\n\n")
                    
                    # Add firmware analysis results if available
                    if bin_results or iot_results:
                        f.write("## Firmware Analysis\n\n")
                        
                        if bin_results:
                            f.write("### Binary Analysis\n\n")
                            for category, files in bin_results.items():
                                f.write(f"#### {category}\n\n")
                                for file in files:
                                    f.write(f"- {file}\n")
                                f.write("\n")
                        
                        if iot_results:
                            f.write("### IoT-Specific Analysis\n\n")
                            for category, files in iot_results.items():
                                f.write(f"#### {category}\n\n")
                                for file in files:
                                    f.write(f"- {file}\n")
                                f.write("\n")
                        
                        f.write("---\n\n")
                    
                    # Add sensitive file search results if available
                    if files_by_type or pattern_matches:
                        f.write("## Sensitive Information Search\n\n")
                        
                        if files_by_type:
                            f.write("### Found Files\n\n")
                            for file_type, files in files_by_type.items():
                                if files:
                                    f.write(f"#### {file_type} Files\n\n")
                                    for file in files:
                                        f.write(f"- {file}\n")
                                    f.write("\n")
                                else:
                                    f.write(f"#### {file_type} Files\n\n")
                                    f.write("**Not Found**\n\n")
                        
                        if pattern_matches:
                            f.write("### Pattern Matches\n\n")
                            for category, files in pattern_matches.items():
                                if files:
                                    f.write(f"#### {category}\n\n")
                                    for file_path, matches in files.items():
                                        f.write(f"**{file_path}**\n\n")
                                        for match in matches:
                                            f.write(f"- {match}\n")
                                        f.write("\n")
                                else:
                                    f.write(f"#### {category}\n\n")
                                    f.write("**Not Found**\n\n")
                
                print(f"{Colors.GREEN}[+] Report generated: {report_file}{Colors.RESET}")
            
            elif choice == '5':
                # Option 5: Exit
                break
            
            else:
                print(f"{Colors.YELLOW}[!] Invalid choice. Please enter a number between 1 and 5.{Colors.RESET}")
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"{Colors.RED}[!] An error occurred: {e}{Colors.RESET}")
    finally:
        if serial_manager:
            serial_manager.close()
        print(f"{Colors.CYAN}Exiting...{Colors.RESET}")

if __name__ == "__main__":
    main()
