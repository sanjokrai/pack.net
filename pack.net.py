from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys

# ─────────────────────────────────────────────────────────────
# COLOURS
# ─────────────────────────────────────────────────────────────
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