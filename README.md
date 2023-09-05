# Network Monitor & Analyzer (Tshark-like Python Tool)

<p align="center">
  <img src="assets/circle.ico" />
</p>

## About Project (Read it please!)
This python software I wrote, it consists of two parts "scripts" *(CLI & GUI)* choose the one you would see it better for your usage.

## Introduction
This Software allows you to capture and analyze network traffic on a specific network interface, similar to the functionality provided by the **Tshark command-line** utility. With this tool, you can monitor various types of network packets, such as TCP, UDP, ARP, and ICMP, and display information about them in a user-friendly format.

## Features
1. Capture and analyze network packets on a specified network interface.
2. Display information about TCP, UDP, ARP, and ICMP packets.
3. Resolve IP addresses to hostnames for better readability.
4. Supports interruption using `Ctrl+C` to stop packet capture.
5. Color-coded output for easier packet type identification.

## Prerequisites
- Before using the Network Analyzer & Monitor, make sure you have the following prerequisites installed:
   - `Python 3.x`
   - `Colorama`
   - `Scapy`

- You can install the required Python packages using pip:

```comamndline
pip install colorama scapy
```

## Usage
To use the Network Analyzer & Monitor, follow these steps:

1. Clone this repository to your local machine:
    ```commandline
    git clone https://github.com/SaherMuhamed/network-monitor-software.git
    ```

2. Open the `network_analyzer_cli.py` file and specify the network interface you want to monitor by modifying the interface variable:

    ```commandline
    interface = "Realtek RTL8822BE 802.11ac PCIe Adapter"
    ```
    
3. Run the `network_analyzer_cli.py` script:

    ```commandline
    python network_analyzer_cli.py
    ```

- The Network Analyzer & Monitor will start capturing and analyzing network packets on the specified interface. You will see packet information displayed in your terminal.

- To stop packet capture, press `Ctrl+C`. The tool will gracefully terminate and provide a summary of the captured packets.

## Screenshot
![screenshots/screenshot-2023-09-05-105441.png](https://github.com/SaherMuhamed/network-monitor-software/blob/main/screenshots/Screenshot-2023-09-05-105441.png)


## Customization
You can customize the tool's behavior by modifying the packet_sniffer.py script according to your requirements. You can add additional packet processing logic or change the output format to suit your needs.

# Next Part (GUI Edition)

## Overview
This part provides a graphical user interface (GUI) for visualizing network traffic in real-time. This software is built using Python and the Tkinter library for the GUI, as well as Scapy for packet capture and analysis.

## Features
- Real-time packet capture and analysis.
- Display of packet details including packet `number`, `timestamp`, `source`, `destination`, `protocol`, `length`, and `additional information`.
- Support for various network protocols, including `TCP`, `UDP`, `ARP`, and `ICMP`.
- Color-coded packet tags for easy protocol identification.
- HTTP packet detection and display.
- User-friendly interface with customizable columns.
- Also the script support object-oriented programming (OOP), so you can read the code easily and add few more features as methods.

## Screenshots
![screenshots\Screenshot-2023-09-05-111744.png](https://github.com/SaherMuhamed/network-monitor-software/blob/main/screenshots/Screenshot-2023-09-05-111744.png)
![screenshots\Screenshot=2023-09-05=111808.png](https://github.com/SaherMuhamed/network-monitor-software/blob/main/screenshots/Screenshot%3D2023-09-05%3D111808.png)

## Color meaning
- <span style="color:red;">Red packet</span> ==> ARP protocol
- <span style="color:purple;">Purple packet</span> ==> ICMP protocol
- <span style="color:green;">Green packet</span> ==> TCP & HTTP protocol
- <span style="color:blue;">Blue packet</span> ==> UDP protocol

**Note:** Please use this project responsibly and only on networks and systems for which you have authorization. Unauthorized network monitoring may violate privacy and legal regulations.

## Release Date
This software was developed @ 5/9/2023.
