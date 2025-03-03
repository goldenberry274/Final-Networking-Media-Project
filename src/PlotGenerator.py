import os
import matplotlib.pyplot as plt
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import TLS
from scapy.all import rdpcap, Raw
import datetime
from collections import Counter
import numpy as np

# Folder containing PCAP files
pcap_folder = input("Enter file path: ")
plot_folder = "plots"

# Ensure the PCAP folder exists
if not os.path.exists(pcap_folder):
    print(f"Error: Folder '{pcap_folder}' does not exist.")
    exit(1)

os.makedirs(plot_folder, exist_ok=True)

# Available fields for analysis
fields = [
    "Packet Size", "TCP Window Size", "TCP Flags", "TLS Version", "TLS Length",
    "IP Length", "IP TTL"
]

while True:
    print("Select a field to analyze:")
    for i, field in enumerate(fields, 1):
        print(f"{i}. {field}")
    print("0. Exit")

    choice = input("Enter the number corresponding to your choice: ")

    if choice == "0":
        break

    try:
        selected_field = fields[int(choice) - 1]
    except (IndexError, ValueError):
        print("Invalid choice. Please try again.")
        continue

    # Dictionary to store data per PCAP file
    data_dict = {}
    tcp_flag_counters = {}

    # Iterate over all PCAP files in the folder
    for pcap_file in os.listdir(pcap_folder):
        if not (pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng")):
            print(f"Skipping non-PCAP file: {pcap_file}")
            continue

        file_path = os.path.join(pcap_folder, pcap_file)

        try:
            packets = rdpcap(file_path)
        except Exception as e:
            print(f"Error reading {pcap_file}: {e}")
            continue

        if not packets:
            print(f"Warning: {pcap_file} contains no packets and will be skipped.")
            continue

        data_dict[pcap_file] = []
        tcp_flag_counters[pcap_file] = Counter()
        start_time = packets[0].time  # Capture start time

        for packet in packets:
            timestamp = packet.time - start_time  # Relative time
            packet_size = len(packet)
            tcp_win = tcp_flags = None
            tls_version = tls_length = None
            ip_length = ip_ttl = None

            # Extract TCP Header Fields
            if TCP in packet:
                tcp_flags = str(packet[TCP].flags)
                tcp_win = packet[TCP].window
                tcp_flag_counters[pcap_file][tcp_flags] += 1

            # Extract TLS Header Fields
            if TLS in packet:
                tls_version = f"0x{packet[TLS].version:04X}"  # Format as hexadecimal (e.g., 0x0303)
                tls_length = packet[TLS].len

            # Extract IP Header Fields
            if IP in packet:
                ip_length = packet[IP].len
                ip_ttl = packet[IP].ttl

            # Append data based on selection
            if selected_field == "Packet Size":
                data_dict[pcap_file].append((timestamp, packet_size))
            elif selected_field == "TCP Window Size" and tcp_win is not None:
                data_dict[pcap_file].append((timestamp, tcp_win))
            elif selected_field == "TCP Flags" and tcp_flags is not None:
                continue  # TCP flags are handled separately
            elif selected_field == "TLS Version" and tls_version is not None:
                data_dict[pcap_file].append((timestamp, tls_version))
            elif selected_field == "TLS Length" and tls_length is not None:
                data_dict[pcap_file].append((timestamp, tls_length))
            elif selected_field == "IP Length" and ip_length is not None:
                data_dict[pcap_file].append((timestamp, ip_length))
            elif selected_field == "IP TTL" and ip_ttl is not None:
                data_dict[pcap_file].append((timestamp, ip_ttl))

    if selected_field == "TCP Flags":
        plt.figure(figsize=(10, 5))
        colors = plt.cm.viridis(np.linspace(0, 1, len(tcp_flag_counters)))
        flag_labels = list(set(flag for counter in tcp_flag_counters.values() for flag in counter))
        x = np.arange(len(flag_labels))
        width = 0.2

        for i, (pcap_file, counter) in enumerate(tcp_flag_counters.items()):
            values = [counter[flag] for flag in flag_labels]
            plt.bar(x + i * width, values, width=width, label=pcap_file)

        plt.xlabel("TCP Flags")
        plt.ylabel("Count")
        plt.title("TCP Flag Occurrences Across All PCAP Files")
        plt.xticks(x + width * (len(tcp_flag_counters) / 2), flag_labels, rotation=45)
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
    else:
        plt.figure(figsize=(10, 5))
        for pcap_file, values in data_dict.items():
            if values:
                timestamps, values_list = zip(*values)
                plt.plot(timestamps, values_list, marker="o", linestyle="-", alpha=0.7, label=pcap_file)

        plt.xlabel("Time (seconds from start)")
        plt.ylabel(selected_field)
        plt.title(f"{selected_field} Over Time Across All PCAP Files")
        plt.legend()
        plt.grid()

    # Ensure unique filenames for plots
    plot_filename = os.path.join(plot_folder, f"{selected_field.replace(' ', '_')}.png")
    if os.path.exists(plot_filename):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        plot_filename = os.path.join(plot_folder, f"{selected_field.replace(' ', '_')}_{timestamp}.png")

    plt.savefig(plot_filename)
    plt.close()

    print(f"Plot for {selected_field} saved in {plot_folder} as {plot_filename}.")
