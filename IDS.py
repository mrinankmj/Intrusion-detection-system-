import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import random
import time
import re
import logging
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from sklearn.cluster import KMeans

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration options
DDOS_THRESHOLD = 10
MAX_FAILED_LOGINS = 5

# Global variables
ddos_sources = {}
protocols = {}
blocked_ips = []

# Real-time packet capture
def start_capture():
    try:
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()
    except Exception as e:
        logger.error(f"Error starting capture thread: {e}")

def capture_packets():
    try:
        packets = sniff(prn=process_packet)
    except Exception as e:
        logger.error(f"Error capturing packets: {e}")

# DDoS Detection Module
def ddos_detection(packet):
    try:
        source_ip = packet[IP].src
        if source_ip in ddos_sources:
            ddos_sources[source_ip] += 1
        else:
            ddos_sources[source_ip] = 1

        if ddos_sources[source_ip] > DDOS_THRESHOLD:
            ddos_label.config(text=f"DDoS Attack Detected from {source_ip}!")
        else:
            ddos_label.config(text="No DDoS Attack")
    except Exception as e:
        logger.error(f"Error in DDoS detection: {e}")

# Network Traffic Analyzer Module
def analyze_traffic(packet):
    try:
        proto = packet[IP].proto
        if proto in protocols:
            protocols[proto] += 1
        else:
            protocols[proto] = 1

        update_traffic_chart()
    except Exception as e:
        logger.error(f"Error analyzing traffic: {e}")

def update_traffic_chart():
    try:
        traffic_chart.clear()
        protocol_names = list(protocols.keys())
        protocol_counts = list(protocols.values())
        traffic_chart.bar(protocol_names, protocol_counts)
        traffic_chart.set_title("Network Traffic by Protocol")
        traffic_chart.set_xlabel("Protocol")
        traffic_chart.set_ylabel("Packet Count")
        traffic_canvas.draw()
    except Exception as e:
        logger.error(f"Error updating traffic chart: {e}")

# Intrusion Prevention System (IPS) Module
def login_attempt(ip):
    try:
        if ip not in failed_logins:
            failed_logins[ip] = 1
        else:
            failed_logins[ip] += 1

        if failed_logins[ip] > MAX_FAILED_LOGINS:
            blocked_ips.append(ip)
            ips_text.insert(tk.END, f"IP {ip} blocked due to too many failed login attempts.\n")
            ips_text.see(tk.END)
    except Exception as e:
        logger.error(f"Error in login attempt: {e}")

# Process incoming packets
def process_packet(packet):
    try:
        ddos_detection(packet)
        analyze_traffic(packet)
        detect_signatures(packet)
        detect_anomalies(packet)
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

# Create the main window
root = tk.Tk()
root.title("Intrusion Detection System")

# DDoS Detection Module UI
ddos_frame = tk.LabelFrame(root, text="DDoS Detection")
ddos_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
ddos_button = tk.Button(ddos_frame, text="Start Capture", command=start_capture)
ddos_button.pack(pady=10)
ddos_label = tk.Label(ddos_frame, text="")
ddos_label.pack()

# Network Traffic Analyzer Module UI
traffic_frame = tk.LabelFrame(root, text="Network Traffic Analyzer")
traffic_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
traffic_canvas = FigureCanvasTkAgg(plt.Figure(figsize=(6, 4)), master=traffic_frame)
traffic_canvas.get_tk_widget().pack()
traffic_chart = traffic_canvas.figure.add_subplot(111)

# Intrusion Prevention System (IPS) Module UI
ips_frame = tk.LabelFrame(root, text="Intrusion Prevention System")
ips_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
ips_text = scrolledtext.ScrolledText(ips_frame, height=10, width=60)
ips_text.pack()

# Run the main loop
root.mainloop()
