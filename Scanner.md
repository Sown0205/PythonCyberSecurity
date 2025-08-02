# Scanner program

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

Then, install required modules for the code, such as time, argparse,datetime, re, threading and scapy, by opening the cmd and type

```bash
pip install time datetime re argparse threading scapy
```

## How to use

Clone the repo from Github to the workspace

```bash
git clone https://github.com/Sown0205/PythonCyberSecurity.git
```
Then use the main file to run the code

Caution: Running scanner program will require root priviliges, as the scanning process won't be complete without the highest access from the user. If the user try to run this program without root priviliges, it will return "Access denied" or "Limited access" error.

Solution: Always use 'sudo' to run the program with highest access
```bash
sudo python3 Scanner.py --target <target IP> --ports <single or mutiple ports scanning>  || sudo python3 Scanner.py --target <target IP> --range <port range scanning>
```

Required flags: 

- --target: Target IP address
- --ports: Target ports (can be both singular or multiple ports), (e.g --ports 445 or --ports 80,139,445)
- --range: Target port range (e.g --range 1-1000). Caution: When speicfy the port range, the hyphen mark ("-") is required.

## Error Exception Handling
- Invalid IP address
- Invalid port input (port must be a number)
- Invalid port value (port must be in range from 1 to 65535)
- Invalid port range (start port must be smaller than end port)
- Invalid range format (Hyphen (-) is required)
- Invalid input format (must include --ports or --range)
- Missing required arguments (--target and --ports or --range)


## Contributing

This is just a project for fun, and also for my learnings as I want to know more about programming and cyber security.

Pull requests are available if you want to contribute to this personal project