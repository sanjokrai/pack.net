from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys

# COLOURS

BG      = "#0d1117"
PANEL   = "#161b22"
GREEN   = "#2ea043"
RED     = "#da3633"
AMBER   = "#d29922"
CYAN    = "#388bfd"
MAGENTA = "#a371f7"
TEXT    = "#e6edf3"
DIM     = "#8b949e"
BORDER  = "#30363d"

MONO = "Courier"

PROTO_COLORS = {
    "TCP":   "#388bfd",
    "UDP":   "#2ea043",
    "ICMP":  "#d29922",
    "OTHER": "#a371f7",
}


# GLOBAL STATE — parallel list custom data structure

g_timestamps = []
g_src_ips    = []
g_dst_ips    = []
g_protocols  = []
g_src_ports  = []
g_dst_ports  = []
g_sizes      = []
g_raw_bytes  = []

g_total = 0
g_tcp   = 0
g_udp   = 0
g_icmp  = 0
g_other = 0

is_sniffing    = False
current_filter = "ALL"
packet_limit   = 0
iface          = None

# GUI widget references
root        = None
tree        = None
detail_text = None
hex_text    = None
btn_start   = None
filter_var  = None
iface_var   = None
limit_var   = None
lbl_state   = None
lbl_total   = None
lbl_tcp     = None
lbl_udp     = None
lbl_icmp    = None
lbl_other   = None


# FUNCTION 1 — get_protocol_name

def get_protocol_name(proto_num):
    """Converts IP protocol number to a readable string."""
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, "OTHER")


# FUNCTION 2 — get_ports

def get_ports(packet):
    """Extracts source and destination port numbers from a packet."""
    if packet.haslayer(TCP):
        return str(packet[TCP].sport), str(packet[TCP].dport)
    if packet.haslayer(UDP):
        return str(packet[UDP].sport), str(packet[UDP].dport)
    return "---", "---"

# FUNCTION 3 — store_packet

def store_packet(ts, src_ip, dst_ip, proto, sport, dport, size, raw):
    """Appends packet metadata into parallel lists (custom data structure)."""
    g_timestamps.append(ts)
    g_src_ips.append(src_ip)
    g_dst_ips.append(dst_ip)
    g_protocols.append(proto)
    g_src_ports.append(sport)
    g_dst_ports.append(dport)
    g_sizes.append(size)
    g_raw_bytes.append(raw)
