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


# FUNCTION 4 — format_hex_dump

def format_hex_dump(raw_bytes, bytes_per_row=16):
    """Converts raw bytes into structured hex dump rows."""
    rows = []
    for offset in range(0, len(raw_bytes), bytes_per_row):
        chunk      = raw_bytes[offset: offset + bytes_per_row]
        addr       = f"{offset:04x}"
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        rows.append((addr, hex_part, ascii_part))
    return rows



# FUNCTION 5 — clear_data
def clear_data():
    """Clears all captured packet data and resets counters."""
    global g_total, g_tcp, g_udp, g_icmp, g_other
    for lst in (g_timestamps, g_src_ips, g_dst_ips, g_protocols,
                g_src_ports, g_dst_ports, g_sizes, g_raw_bytes):
        lst.clear()
    g_total = g_tcp = g_udp = g_icmp = g_other = 0


# FUNCTION 6 — process_packet

def process_packet(packet):
    """Scapy callback — extracts metadata, stores it, updates GUI."""
    global g_total, g_tcp, g_udp, g_icmp, g_other, is_sniffing

    if not packet.haslayer(IP):
        return

    ts           = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src          = packet[IP].src
    dst          = packet[IP].dst
    proto        = get_protocol_name(packet[IP].proto)
    sport, dport = get_ports(packet)
    size         = len(packet)
    raw          = bytes(packet)

    store_packet(ts, src, dst, proto, sport, dport, size, raw)
    g_total += 1

    if proto == "TCP":    g_tcp   += 1
    elif proto == "UDP":  g_udp   += 1
    elif proto == "ICMP": g_icmp  += 1
    else:                 g_other += 1

    root.after(0, add_packet_row, len(g_timestamps) - 1)
    root.after(0, update_stats)

    if packet_limit > 0 and g_total >= packet_limit:
        is_sniffing = False
        root.after(0, set_stopped_state)

# FUNCTION 7 — run_sniff

def run_sniff(iface_name):
    """Runs Scapy sniff() in a background daemon thread."""
    try:
        sniff(iface=iface_name, prn=process_packet,
              store=False, stop_filter=lambda _: not is_sniffing)
    except Exception as e:
        root.after(0, lambda: messagebox.showerror(
            "Error", f"{e}\n\nRun as Administrator / sudo."))
        root.after(0, set_stopped_state)

# FUNCTION 8 — toggle_capture
# ─────────────────────────────────────────────────────────────
def toggle_capture():
    """Starts or stops packet capture."""
    global is_sniffing, iface, packet_limit

    if is_sniffing:
        is_sniffing = False
        set_stopped_state()
        return

    iface_val = iface_var.get().strip()
    iface = iface_val if iface_val else None
    try:
        packet_limit = int(limit_var.get().strip() or "0")
    except ValueError:
        packet_limit = 0

    is_sniffing = True
    btn_start.config(text="■  STOP", bg=RED, fg="black")
    lbl_state.config(text="● CAPTURING", fg=GREEN)

    threading.Thread(target=run_sniff, args=(iface,), daemon=True).start()

    # FUNCTION 9 — set_stopped_state

def set_stopped_state():
    """Resets GUI controls after capture stops."""
    btn_start.config(text="▶  START", bg=GREEN, fg="black")
    lbl_state.config(text="● IDLE", fg=DIM)

    # FUNCTION 10 — on_filter_change

def on_filter_change(event=None):
    """Updates filter and rebuilds the packet table."""
    global current_filter
    current_filter = filter_var.get()
    tree.delete(*tree.get_children())
    for i in range(len(g_protocols)):
        add_packet_row(i)

# FUNCTION 11 — on_clear

def on_clear():
    """Clears all data after user confirmation."""
    if messagebox.askyesno("Clear", f"Clear {g_total} captured packets?"):
        clear_data()
        tree.delete(*tree.get_children())
        update_stats()
        for w in (detail_text, hex_text):
            w.config(state="normal")
            w.delete("1.0", "end")
            w.config(state="disabled")


# FUNCTION 12 — on_packet_select

def on_packet_select(event=None):
    """Shows details and hex dump for the selected packet."""
    selected = tree.selection()
    if not selected:
        return
    idx = int(tree.item(selected[0])["values"][0]) - 1
    show_detail(idx)


# FUNCTION 13 — add_packet_row

def add_packet_row(idx):
    """Adds one packet row to the table if it matches the filter."""
    proto = g_protocols[idx]
    if current_filter != "ALL" and proto != current_filter:
        return
    src = f"{g_src_ips[idx]}:{g_src_ports[idx]}"
    dst = f"{g_dst_ips[idx]}:{g_dst_ports[idx]}"
    tree.insert("", "end",
                values=(idx + 1, g_timestamps[idx],
                        src, dst, proto, f"{g_sizes[idx]}B"),
                tags=(proto,))
    tree.yview_moveto(1)

    # FUNCTION 14 — update_stats

def update_stats():
    """Updates all stat labels in the sidebar."""
    lbl_total.config(text=f"Total:  {g_total:,}")
    lbl_tcp.config(text=f"TCP:    {g_tcp:,}")
    lbl_udp.config(text=f"UDP:    {g_udp:,}")
    lbl_icmp.config(text=f"ICMP:   {g_icmp:,}")
    lbl_other.config(text=f"Other:  {g_other:,}")



# FUNCTION 15 — show_detail

def show_detail(idx):
    """Displays metadata and hex dump for a selected packet."""
    info = (
        f"Packet  : #{idx + 1}\n"
        f"Time    : {g_timestamps[idx]}\n"
        f"Proto   : {g_protocols[idx]}\n"
        f"Source  : {g_src_ips[idx]}:{g_src_ports[idx]}\n"
        f"Dest    : {g_dst_ips[idx]}:{g_dst_ports[idx]}\n"
        f"Size    : {g_sizes[idx]} bytes\n"
    )
    detail_text.config(state="normal")
    detail_text.delete("1.0", "end")
    detail_text.insert("end", info)
    detail_text.config(state="disabled")

    rows = format_hex_dump(g_raw_bytes[idx])
    lines = ["OFFSET   HEX                                                ASCII\n",
             "-" * 65 + "\n"]
    for addr, hex_part, ascii_part in rows:
        lines.append(f"{addr}   {hex_part:<48}  {ascii_part}\n")

    hex_text.config(state="normal")
    hex_text.delete("1.0", "end")
    hex_text.insert("end", "".join(lines))
    hex_text.config(state="disabled")
