# IoT Scout

IoT Scout is a Python-based tool designed to monitor processes on embedded devices via a serial connection. It provides a process table of running processes and an interactive menu to execute commands found in the /bin directory of the device. The tool classifies commands as standard or non-standard based on the Filesystem Hierarchy Standard (FHS) 3.0, highlighting non-standard commands for further investigation.

## Features
- Monitors running processes on an embedded device using the ps command.
- Lists commands in the /bin directory of the device, classifying them as standard (green) or non-standard (red).
- Provides an interactive menu to run /bin commands and capture their output.
- Includes robust error handling for serial port issues and invalid inputs.

## Requirements

To run IoT Scout, you'll need the following dependencies:

- Python 3.x
- pyserial
- pandas
- tabulate
- colorama

Install the dependencies using pip:
```bash
pip install pyserial pandas tabulate colorama
```

## Usage
- **Configure the Serial Port:**
  - Open the script and adjust the port variable to match your device's serial port (e.g., /dev/ttyUSB0 on Linux or COM3 on Windows).
- **Example:**
  ``` python
  port = "/dev/ttyUSB0"
  ```
- **Run the Script:**
  - Execute the script in a Python environment:
  ``` bash
  python iot_scout.py
  ```
  - The script will:
    - Wait 20 seconds for the device to boot.
    - Show a process table with running processes (from the ps command).
    - Present a numbered menu of commands in /bin.
    - Allow you to enter a number to run a command and see its output, or 'q' to quit.
  - Interact with the Menu:
    - After the process table, you'll see a list of `/bin` commands with numbers.
    - Enter the number of a command to execute it on the device and see the output.
    - Enter 'q' to exit the script.

## Example Output
``` text
      ____    ______   _____                  __ 
     /  _/___/_  __/  / ___/_________  __  __/ /_
     / // __ \/ /     \__ \/ ___/ __ \/ / / / __/
   _/ // /_/ / /     ___/ / /__/ /_/ / /_/ / /_  
  /___/\____/_/     /____/\___/\____/\__,_/\__/ 
                                             

Author: Darkma773r (https://github.com/darkmatter91)

[+] Waiting for device to boot (20 seconds)...
[+] Device boot wait complete.
=== Process List (Timestamp: 2023-10-25 14:30:45) ===
╒═══════╤═══════╤════════════════════════════════════╤═════════════════════════════════╕
│ PID   │ USER  │ CMD                                │ Description                     │
╞═══════╪═══════╪════════════════════════════════════╪═════════════════════════════════╡
│ 1     │ root  │ init                               │ Initial process                 │
│ 2     │ root  │ [kworker/0:0]                      │ Kernel thread: kworker          │
│ 10    │ root  │ /bin/cat                           │ Standard Command: cat           │
│ 15    │ root  │ < dhcpd /var/tmp/dconf/udhcpd.conf │ DHCP server                     │
│ 20    │ root  │ suspicious_app                     │ Unknown command: suspicious_app │
╘═══════╧═══════╧════════════════════════════════════╧═════════════════════════════════╛

[+] Enabled Commands in /bin:
1. ash (Non-Standard)
2. bash (Standard Command)
3. cat (Standard Command)
4. wscd (Non-Standard)

[+] Enter the number of the command to run (or 'q' to quit):
> 1

[+] Running command: ash
[+] Output:
[Output of ash command]

[+] Enter the number of the command to run (or 'q' to quit):
> q
Exiting...
```
## Disclaimer

This tool is provided for educational purposes only. The author, Darkma773r, is not responsible for any actions taken using this script, including but not limited to misuse, damage to systems, or illegal activities. Use this tool at your own risk and ensure compliance with all applicable laws and regulations. Always obtain proper authorization before interacting with any device or system.

## License

This project is licensed under the MIT License. See the  file for details.


