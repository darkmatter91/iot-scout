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

