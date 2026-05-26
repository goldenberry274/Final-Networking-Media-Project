# Final Networking Media Project

This repository contains the final project for the Communication Networks course at Ariel University.

The project focuses on network traffic analysis, protocol inspection, and visualization of networking-related data extracted from packet captures.

---

# Project Structure

## Paper

The paper written for this project is divided into three main sections:

### 1. Technical Questions
Answers to theoretical and technical questions related to communication networks and course material.

### 2. Research Summaries
Summaries and discussions of various networking-related studies and technologies, including topics such as:
- Modern encryption protocols
- Network security
- TLS-related technologies
- Internet communication protocols

### 3. Traffic Analysis & Plots
Analysis and visualization of different networking fields extracted from captured traffic, including:
- TCP header fields
- TLS fields
- IP header fields

This section also includes explanations and interpretations of the generated plots.

---

# Source Code

The `src` directory contains the Python program used to analyze packet captures and generate plots for various networking protocol fields.

The program supports analysis of:
- IP packets
- TCP packets
- TLS traffic

Generated plots are automatically saved for later inspection.

---

# Results

The `res` directory contains:
- All generated plots
- Wireshark-generated visualizations
- Plots created using the custom Python plot generator

---

# Requirements

## Python Version

The project was developed using:
Python 3.12.3

## Python Packages

os
matplotlib.pyplot
scapy.layers.inet
scapy.layers.tls.all
scapy.all
datetime
collections
numpy

## How to Install
pip install matplotlib scapy numpy

# Technologies Used
This project was built using the following technologies and tools:

Python 3.12.3
Scapy
Matplotlib
NumPy
Wireshark
PCAP / PCAPNG packet analysis

# How to Run
## Folder Structure

The program expects a directory named:

## Recordings

This directory should contain .pcap or .pcapng files.

The folder must be located at the same directory level as the Python source code.

# Running the Program

Run the Python script from the src directory:

python main.py

## The program will:

Check whether a Recordings directory exists
Ask the user to choose a field to analyze
Parse all .pcap and .pcapng files
Generate plots for the selected field
Save the generated plots into a plots directory

If the plots directory does not exist, it will be created automatically.

# Features

Automatic parsing of packet capture files
Visualization of networking protocol fields
Support for TCP, TLS, and IP analysis
Automatic plot generation and export
Integration with Wireshark-based analysis

```txt id="x4m90n"
Python 3.12.3
