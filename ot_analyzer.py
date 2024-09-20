# Author: Jordi Ubach @hack3007
# Email: jordiubach@protonmail.com
# License: Open source
# Disclaimer: The use of this tool is free and under the responsibility of each user.
import sys
import csv
import os
from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime

import sys
import csv
import os
from scapy.all import rdpcap, IP, TCP, UDP
from datetime import datetime

def analyze_pcap(file_pcap, file_out, file_ports):
    # Hash of 100 common OT/IOT ports and their descriptions
    ot_iot_ports = {
        '21': 'FTP - File Transfer Protocol',
        '22': 'SSH - Secure Shell',
        '23': 'Telnet',
        '25': 'SMTP - Simple Mail Transfer Protocol',
        '80': 'HTTP - Hypertext Transfer Protocol',
        '102': 'Siemens S7 - Industrial Control System Protocol',
        '123': 'NTP - Network Time Protocol',
        '161': 'SNMP - Simple Network Management Protocol',
        '162': 'SNMP Trap',
        '443': 'HTTPS - HTTP Secure',
        '502': 'Modbus TCP - Industrial Control System Protocol',
        '530': 'RPC - Remote Procedure Call',
        '1089': 'FF Annunciation',
        '1090': 'FF Fieldbus Message Specification',
        '1091': 'FF System Management',
        '1541': 'Foxboro DCS',
        '1911': 'Foxboro DCS',
        '1962': 'PCWorx - Industrial Control System Protocol',
        '2222': 'EtherCAT - Industrial Ethernet Protocol',
        '2404': 'IEC 60870-5-104 - Power System Control and Monitoring',
        '2455': 'WAGO Industrial Control System',
        '2540': 'LonWorks - Building Automation Protocol',
        '2541': 'LonWorks2 - Building Automation Protocol',
        '3000': 'HPOM - HP Operations Manager',
        '3480': 'HP OpenView Network Node Manager',
        '4000': 'Emerson DeltaV DCS',
        '4840': 'OPC UA - Open Platform Communications Unified Architecture',
        '4841': 'OPC UA Discovery Server',
        '4911': 'Niagara Fox',
        '5006': 'Siemens S7 - Industrial Control System Protocol',
        '5007': 'Siemens S7 - Industrial Control System Protocol',
        '5094': 'HART-IP - Highway Addressable Remote Transducer IP',
        '5800': 'VNC - Virtual Network Computing',
        '6379': 'Redis Database',
        '7000': 'Schneider Electric Citect SCADA',
        '7400': 'CODESYS - Industrial Control System Protocol',
        '7401': 'CODESYS - Industrial Control System Protocol',
        '7402': 'CODESYS - Industrial Control System Protocol',
        '7626': 'SIMATICS7 - Siemens Industrial Control System',
        '7700': 'Schneider Electric Citect SCADA',
        '9100': 'PDL Data Stream - Printer Job Language',
        '9600': 'OMRON FINS - Industrial Control System Protocol',
        '10000': 'Schneider Electric Citect SCADA',
        '11112': 'DICOM - Digital Imaging and Communications in Medicine',
        '18245': 'GE SRTP - GE Intelligent Platforms SRTP',
        '18246': 'GE SRTP - GE Intelligent Platforms SRTP',
        '20000': 'DNP3 - Distributed Network Protocol',
        '20547': 'ProConOS - Industrial Control System Protocol',
        '34962': 'PROFInet RT Unicast',
        '34963': 'PROFInet RT Multicast',
        '34964': 'PROFInet Context Manager',
        '34980': 'EtherCAT - Industrial Ethernet Protocol',
        '38589': 'Mitsubishi MELSEC-Q',
        '38593': 'Mitsubishi MELSEC-Q',
        '41100': 'Siemens SICAM',
        '44818': 'EtherNet/IP - Industrial Ethernet Protocol',
        '45678': 'Schneider Electric ProWorx',
        '47808': 'BACnet - Building Automation and Control Networks',
        '48898': 'ADS - Automation Device Specification',
        '50000': 'Siemens S7 Scalance',
        '55000': 'FL-net - Industrial Control System Protocol',
        '55003': 'ABB Ranger 2003',
        '56001': 'Guardian AST',
        '62900': 'ABB Ranger 2003',
        '1024': 'Wago 750',
        '1025': 'Wago 750',
        '1026': 'Wago 750',
        '1027': 'Wago 750',
        '1028': 'Wago 750',
        '1029': 'Wago 750',
        '1030': 'Wago 750',
        '1031': 'Wago 750',
        '1962': 'PCWorx - Industrial Control System Protocol',
        '2222': 'EtherCAT - Industrial Ethernet Protocol',
        '2404': 'IEC 60870-5-104 - Power System Control and Monitoring',
        '4000': 'Emerson DeltaV DCS',
        '4840': 'OPC UA - Open Platform Communications Unified Architecture',
        '4843': 'OPC UA Discovery Server',
        '4911': 'Niagara Fox',
        '5006': 'Siemens S7 - Industrial Control System Protocol',
        '5007': 'Siemens S7 - Industrial Control System Protocol',
        '5094': 'HART-IP - Highway Addressable Remote Transducer IP',
        '9600': 'OMRON FINS - Industrial Control System Protocol',
        '20000': 'DNP3 - Distributed Network Protocol',
        '44818': 'EtherNet/IP - Industrial Ethernet Protocol',
        '47808': 'BACnet - Building Automation and Control Networks',
        '48898': 'ADS - Automation Device Specification',
        '502': 'Modbus TCP - Industrial Control System Protocol',
        '1089': 'Foundation Fieldbus HSE',
        '1090': 'Foundation Fieldbus HSE',
        '1091': 'Foundation Fieldbus HSE',
        '2222': 'Rockwell CSP',
        '2404': 'IEC 60870-5-104',
        '5094': 'HART-IP',
        '9600': 'OMRON FINS',
        '20000': 'DNP3',
        '44818': 'EtherNet/IP',
        '47808': 'BACnet',
        '48898': 'ADS/AMS'
    }

    # Rest of the function remains the same
    # ...

# Rest of the script remains the same
# ...

    # Read custom ports from FILE_PORTS
    custom_ports = {}
    with open(file_ports, 'r') as f:
        for line in f:
            port, protocol = line.strip().split('/')
            if port and protocol:
                custom_ports[port] = protocol

    # Read PCAP file
    try:
        packets = rdpcap(file_pcap)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        print(f"File details:")
        print(f"  Path: {file_pcap}")
        print(f"  Size: {os.path.getsize(file_pcap)} bytes")
        with open(file_pcap, 'rb') as f:
            print(f"  Magic bytes: {f.read(4).hex()}")
        return

    # Open output CSV file
    with open(file_out, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Date/Time', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'MAC Address', 'Packet Size', 'OT/IOT Description'])

        for packet in packets:
            try:
                if IP in packet:
                    # Convert timestamp to float before passing to datetime
                    try:
                        timestamp = datetime.fromtimestamp(float(packet.time)).strftime('%y/%m/%d - %H:%M:%S')
                    except ValueError:
                        timestamp = "Unknown"
                    
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    mac_address = packet.src
                    packet_size = len(packet)

                    if TCP in packet:
                        port = str(packet[TCP].dport)
                    elif UDP in packet:
                        port = str(packet[UDP].dport)
                    else:
                        continue

                    ot_iot_desc = ot_iot_ports.get(port) or custom_ports.get(port) or ''

                    csv_writer.writerow([timestamp, src_ip, dst_ip, port, protocol, mac_address, packet_size, ot_iot_desc])
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue

    print(f"Analysis complete. Results saved to {file_out}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python script.py FILE_PCAP FILE_OUT FILE_PORTS")
        sys.exit(1)

    file_pcap = sys.argv[1]
    file_out = sys.argv[2]
    file_ports = sys.argv[3]

    analyze_pcap(file_pcap, file_out, file_ports)
