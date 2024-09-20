# OT Analyzer

OT Analyzer is a Python script that analyzes PCAP (Packet Capture) files to identify and log network traffic related to Operational Technology (OT) and Internet of Things (IoT) protocols. This tool is particularly useful for industrial control system (ICS) security professionals and network administrators working with OT/IoT environments.

## Features

- Analyzes PCAP files for OT/IoT network traffic
- Identifies common OT/IoT protocols based on port numbers
- Supports custom port-to-protocol mappings
- Generates a CSV report with detailed packet information
- Includes a pre-defined list of 100 common OT/IoT ports and their descriptions

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/jubachm/OT_TOOLS.git
   cd ot_tools
   ```

2. Install the required dependencies:
   ```
   pip install scapy
   ```

## Usage

Run the script from the command line with the following syntax:

```
python ot_analyzer.py FILE_PCAP FILE_OUT FILE_PORTS
```

Where:
- `FILE_PCAP`: Path to the input PCAP file
- `FILE_OUT`: Path to the output CSV file
- `FILE_PORTS`: Path to a file containing custom port-to-protocol mappings

Example:
```
python ot_analyzer.py capture.pcap analysis_results.csv custom_ports.txt
```

## Custom Port Mappings

You can define custom port-to-protocol mappings in a separate file. Each line in this file should follow the format:

```
port/protocol
```

Example `custom_ports.txt`:
```
8080/HTTP-ALT
9100/JetDirect
```

## Output

The script generates a CSV file with the following columns:

- Date/Time
- Source IP
- Destination IP
- Port
- Protocol
- MAC Address
- Packet Size
- OT/IOT Description

## Pre-defined OT/IoT Ports

The script includes a predefined list of 100 common OT/IoT ports and their descriptions. Some examples include:

- 102: Siemens S7 - Industrial Control System Protocol
- 502: Modbus TCP - Industrial Control System Protocol
- 44818: EtherNet/IP - Industrial Ethernet Protocol
- 47808: BACnet - Building Automation and Control Networks

For a complete list, please refer to the script source code.

## Error Handling

The script includes error handling for common issues such as:
- Invalid PCAP file format
- Missing input files
- Errors during packet processing

Error messages will be displayed in the console output.

## Contributing

Contributions to improve OT Analyzer are welcome. Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

## License

[MIT License](LICENSE)

## Disclaimer

This tool is intended for use by authorized personnel in controlled environments. Always ensure you have the necessary permissions before capturing or analyzing network traffic.
