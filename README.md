# PythonCyberSecurity

Hello, my name is Sown and this is my little project for fun and for my learnings

## Overview

This is a basic Python program that will perform a SYN port scanning on a targeted IP address.

The program will send a SYN packet to the IP address available ports

If SYN-ACK is received from a port, it means that the port is OPENED, and the program will send a RST to close it

If RST-ACK is received, it means that the port is CLOSED

Filtered or unknown status ports will be ignored

Then, the main function will handle arguments from Linux CLI commands, perform the scan process and then print the results. It also has a timer to count the amount of time that the process took place

## Required Dependencies and Modules

To use this code, make sure that you have installed Python.exe and pip first

Then, install required modules for the code, such as time, argparse, threading and scapy, by opening the cmd and type

```bash
pip install time argparse threading scapy
```

## How to use

This code is tested on Kali Linux, but you can test on any Debian-based machines

First, create a new file and set its names (e.g syn_scanner.py)

```bash
sudo nano syn_scanner.py
```

Then, copy and paste the code into the newly created file, then save it (Ctrl + O, Enter, Ctrl + X)

Run the command
```bash
sudo python3 syn_scanner.py (target IP) (target ports)
```

There are 2 command arguments: --ports and --range

--ports: Scan a single or multiple ports (e.g --ports 145 ; --ports 139,145,445)

--range: Scan a range of ports (e.g --range 1-1000 ; the hyphen (-) is required to seperate start port and end port)

If you dont want to copy and paste the code, you can clone the repository instead then use the file to run

```bash
sudo git clone https://github.com/Sown0205/PythonCyberSecurity.git
```

## Error Exception Handling
- Invalid IP address
- Invalid port input (port must be a number)
- Invalid port value (port must be in range from 1 to 65535)
- Invalid port range (start port must be smaller than end port)
- Invalid range format (Hyphen (-) is required)
- Invalid input format (must include --ports or --range)


## Contributing

This is just a project for fun, and also for my learnings as I want to know more about programming and cyber security.

Im just a beginner so dont be too harsh to me :)

If you have any cool ideas or advices, please let me know. You can commit your changes and I will check for it. Pull requests are available so feel free to commit

Thank you for reading this