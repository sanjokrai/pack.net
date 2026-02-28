from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading

# ─────────────────────────────────────────────────────────────
# GLOBAL STATE — parallel list custom data structure
# ─────────────────────────────────────────────────────────────
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

    # GUI callbacks — injected by frontend at startup
    if _gui_on_packet:
        _gui_on_packet(len(g_timestamps) - 1)

    if packet_limit > 0 and g_total >= packet_limit:
        is_sniffing = False
        if _gui_on_stop:
            _gui_on_stop()



# FUNCTION 7 — run_sniff

def run_sniff(iface_name):
    """Runs Scapy sniff() in a background daemon thread."""
    try:
        sniff(iface=iface_name, prn=process_packet,
              store=False, stop_filter=lambda _: not is_sniffing)
    except Exception as e:
        if _gui_on_error:
            _gui_on_error(str(e))
        if _gui_on_stop:
            _gui_on_stop()



# GUI CALLBACK HOOKS — set by frontend.py at startup

_gui_on_packet = None   # called with packet index after each capture
_gui_on_stop   = None   # called when capture stops
_gui_on_error  = None   # called with error message string


def register_gui_callbacks(on_packet=None, on_stop=None, on_error=None):
    """Frontend calls this once to wire GUI update callbacks into the backend."""
    global _gui_on_packet, _gui_on_stop, _gui_on_error
    _gui_on_packet = on_packet
    _gui_on_stop   = on_stop
    _gui_on_error  = on_error



# CAPTURE CONTROL — called by frontend toggle_capture()

def start_capture(iface_name, limit):
    """Sets capture state and launches background sniff thread."""
    global is_sniffing, iface, packet_limit
    iface        = iface_name if iface_name else None
    packet_limit = limit
    is_sniffing  = True
    threading.Thread(target=run_sniff, args=(iface,), daemon=True).start()


def stop_capture():
    """Signals the background thread to stop capturing."""
    global is_sniffing
    is_sniffing = False