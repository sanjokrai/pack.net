import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys

import backend


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



# FUNCTION 8 — toggle_capture

def toggle_capture():
    """Starts or stops packet capture."""
    if backend.is_sniffing:
        backend.stop_capture()
        set_stopped_state()
        return

    iface_val = iface_var.get().strip()
    try:
        limit = int(limit_var.get().strip() or "0")
    except ValueError:
        limit = 0

    btn_start.config(text="■  STOP", bg=RED, fg="black")
    lbl_state.config(text="● CAPTURING", fg=GREEN)

    backend.start_capture(iface_val, limit)



# FUNCTION 9 — set_stopped_state
def set_stopped_state():
    """Resets GUI controls after capture stops."""
    btn_start.config(text="▶  START", bg=GREEN, fg="black")
    lbl_state.config(text="● IDLE", fg=DIM)



# FUNCTION 10 — on_filter_change

def on_filter_change(event=None):
    """Updates filter and rebuilds the packet table."""
    backend.current_filter = filter_var.get()
    tree.delete(*tree.get_children())
    for i in range(len(backend.g_protocols)):
        add_packet_row(i)



# FUNCTION 11 — on_clear

def on_clear():
    """Clears all data after user confirmation."""
    if messagebox.askyesno("Clear", f"Clear {backend.g_total} captured packets?"):
        backend.clear_data()
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
    proto = backend.g_protocols[idx]
    if backend.current_filter != "ALL" and proto != backend.current_filter:
        return
    src = f"{backend.g_src_ips[idx]}:{backend.g_src_ports[idx]}"
    dst = f"{backend.g_dst_ips[idx]}:{backend.g_dst_ports[idx]}"
    tree.insert("", "end",
                values=(idx + 1, backend.g_timestamps[idx],
                        src, dst, proto, f"{backend.g_sizes[idx]}B"),
                tags=(proto,))
    tree.yview_moveto(1)



# FUNCTION 14 — update_stats

def update_stats():
    """Updates all stat labels in the sidebar."""
    lbl_total.config(text=f"Total:  {backend.g_total:,}")
    lbl_tcp.config(text=f"TCP:    {backend.g_tcp:,}")
    lbl_udp.config(text=f"UDP:    {backend.g_udp:,}")
    lbl_icmp.config(text=f"ICMP:   {backend.g_icmp:,}")
    lbl_other.config(text=f"Other:  {backend.g_other:,}")



# FUNCTION 15 — show_detail

def show_detail(idx):
    """Displays metadata and hex dump for a selected packet."""
    info = (
        f"Packet  : #{idx + 1}\n"
        f"Time    : {backend.g_timestamps[idx]}\n"
        f"Proto   : {backend.g_protocols[idx]}\n"
        f"Source  : {backend.g_src_ips[idx]}:{backend.g_src_ports[idx]}\n"
        f"Dest    : {backend.g_dst_ips[idx]}:{backend.g_dst_ports[idx]}\n"
        f"Size    : {backend.g_sizes[idx]} bytes\n"
    )
    detail_text.config(state="normal")
    detail_text.delete("1.0", "end")
    detail_text.insert("end", info)
    detail_text.config(state="disabled")

    rows = backend.format_hex_dump(backend.g_raw_bytes[idx])
    lines = ["OFFSET   HEX                                                ASCII\n",
             "-" * 65 + "\n"]
    for addr, hex_part, ascii_part in rows:
        lines.append(f"{addr}   {hex_part:<48}  {ascii_part}\n")

    hex_text.config(state="normal")
    hex_text.delete("1.0", "end")
    hex_text.insert("end", "".join(lines))
    hex_text.config(state="disabled")



# GUI CALLBACK HANDLERS — passed to backend via register_gui_callbacks()

def _on_packet(idx):
    """Scheduled on main thread: adds row and refreshes stats."""
    root.after(0, add_packet_row, idx)
    root.after(0, update_stats)


def _on_stop():
    """Scheduled on main thread: resets toolbar state."""
    root.after(0, set_stopped_state)


def _on_error(msg):
    """Scheduled on main thread: shows error dialog."""
    root.after(0, lambda: messagebox.showerror(
        "Error", f"{msg}\n\nRun as Administrator / sudo."))



# FUNCTION 16 — build_header

def build_header(parent):
    """Builds a clean title banner at the top."""
    hdr = tk.Frame(parent, bg=PANEL, pady=10)
    hdr.pack(fill="x")

    tk.Label(hdr, text="PACK-NET",
             font=(MONO, 22, "bold"),
             fg=GREEN, bg=PANEL).pack()

    tk.Label(hdr, text=" Network Packet Analyzer | Ethical Hacking & Cybersecurity Tool",
             font=(MONO, 10),
             fg=DIM, bg=PANEL).pack()

    # green divider line
    tk.Frame(parent, bg=GREEN, height=1).pack(fill="x")



# FUNCTION 17 — build_toolbar

def build_toolbar(parent):
    """Builds the controls toolbar below the header."""
    global btn_start, filter_var, iface_var, limit_var, lbl_state

    bar = tk.Frame(parent, bg=PANEL, pady=6)
    bar.pack(fill="x")

    # centre all controls in one inner frame
    inner = tk.Frame(bar, bg=PANEL)
    inner.pack(anchor="center")

    # START / STOP
    btn_start = tk.Button(inner, text="▶  START",
                          command=toggle_capture,
                          font=(MONO, 11, "bold"),
                          bg=GREEN, fg="black",
                          relief="flat", padx=14, pady=4,
                          cursor="hand2")
    btn_start.pack(side="left", padx=(0, 6))

    # CLEAR
    tk.Button(inner, text="✕  CLEAR", command=on_clear,
              font=(MONO, 10), fg=AMBER, bg=PANEL,
              relief="flat", padx=10, pady=4,
              cursor="hand2").pack(side="left", padx=(0, 18))

    _sep(inner)

    # Filter
    tk.Label(inner, text="Filter:", fg=DIM, bg=PANEL,
             font=(MONO, 9)).pack(side="left")
    filter_var = tk.StringVar(value="ALL")
    cb = ttk.Combobox(inner, textvariable=filter_var,
                      values=["ALL", "TCP", "UDP", "ICMP", "OTHER"],
                      width=7, state="readonly", font=(MONO, 9))
    cb.pack(side="left", padx=(4, 18))
    cb.bind("<<ComboboxSelected>>", on_filter_change)

    _sep(inner)

    # Iface
    tk.Label(inner, text="Iface:", fg=DIM, bg=PANEL,
             font=(MONO, 9)).pack(side="left")
    iface_var = tk.StringVar()
    tk.Entry(inner, textvariable=iface_var, width=10,
             font=(MONO, 9), bg=BG, fg=TEXT,
             insertbackground=GREEN, relief="flat").pack(side="left", padx=(4, 18))

    _sep(inner)

    # Limit
    tk.Label(inner, text="Limit:", fg=DIM, bg=PANEL,
             font=(MONO, 9)).pack(side="left")
    limit_var = tk.StringVar(value="0")
    tk.Entry(inner, textvariable=limit_var, width=6,
             font=(MONO, 9), bg=BG, fg=TEXT,
             insertbackground=GREEN, relief="flat").pack(side="left", padx=(4, 18))

    _sep(inner)

    # Status
    lbl_state = tk.Label(inner, text="● IDLE",
                         font=(MONO, 10, "bold"),
                         fg=DIM, bg=PANEL)
    lbl_state.pack(side="left", padx=(6, 0))

    # second divider
    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")


def _sep(parent):
    """Small vertical separator between toolbar items."""
    tk.Label(parent, text="|", fg=BORDER, bg=PANEL,
             font=(MONO, 9)).pack(side="left", padx=6)



# FUNCTION 18 — build_stats_panel

def build_stats_panel(parent):
    """Builds the left stats sidebar."""
    global lbl_total, lbl_tcp, lbl_udp, lbl_icmp, lbl_other

    frame = tk.Frame(parent, bg=PANEL, width=155)
    frame.pack(side="left", fill="y", padx=(8, 4), pady=8)
    frame.pack_propagate(False)

    tk.Label(frame, text="STATISTICS",
             font=(MONO, 8, "bold"),
             fg=DIM, bg=PANEL).pack(pady=(10, 6))

    lbl_total = tk.Label(frame, text="Total:  0",
                         font=(MONO, 9), fg=TEXT,     bg=PANEL, anchor="w")
    lbl_tcp   = tk.Label(frame, text="TCP:    0",
                         font=(MONO, 9), fg=CYAN,     bg=PANEL, anchor="w")
    lbl_udp   = tk.Label(frame, text="UDP:    0",
                         font=(MONO, 9), fg=GREEN,    bg=PANEL, anchor="w")
    lbl_icmp  = tk.Label(frame, text="ICMP:   0",
                         font=(MONO, 9), fg=AMBER,    bg=PANEL, anchor="w")
    lbl_other = tk.Label(frame, text="Other:  0",
                         font=(MONO, 9), fg=MAGENTA,  bg=PANEL, anchor="w")

    for lbl in (lbl_total, lbl_tcp, lbl_udp, lbl_icmp, lbl_other):
        lbl.pack(fill="x", padx=12, pady=2)



# FUNCTION 19 — build_packet_table

def build_packet_table(parent):
    """Builds the main scrollable packet list table."""
    global tree

    frame = tk.Frame(parent, bg=BG)
    frame.pack(side="left", fill="both", expand=True, pady=8)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("P.Treeview",
                    background=BG, foreground=TEXT,
                    fieldbackground=BG, rowheight=20,
                    font=(MONO, 9))
    style.configure("P.Treeview.Heading",
                    background=PANEL, foreground=DIM,
                    font=(MONO, 9, "bold"))
    style.map("P.Treeview",
              background=[("selected", "#1c2a1c")],
              foreground=[("selected", GREEN)])

    tree = ttk.Treeview(frame,
                        columns=("num", "time", "src", "dst", "proto", "size"),
                        show="headings", style="P.Treeview")

    for col, heading, w in zip(
        ("num", "time", "src", "dst", "proto", "size"),
        ("#",   "TIME", "SOURCE", "DESTINATION", "PROTO", "SIZE"),
        (45,    105,    190,      190,            65,      65)
    ):
        tree.heading(col, text=heading)
        tree.column(col, width=w, anchor="w", stretch=False)

    for proto, color in PROTO_COLORS.items():
        tree.tag_configure(proto, foreground=color)

    vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    tree.bind("<<TreeviewSelect>>", on_packet_select)



# FUNCTION 20 — build_detail_panel

def build_detail_panel(parent):
    """Builds the bottom detail and hex dump panels."""
    global detail_text, hex_text

    tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

    bottom = tk.Frame(parent, bg=BG, height=175)
    bottom.pack(fill="x")
    bottom.pack_propagate(False)

    # left — packet metadata
    left = tk.Frame(bottom, bg=PANEL, width=255)
    left.pack(side="left", fill="y", padx=(8, 2), pady=6)
    left.pack_propagate(False)

    tk.Label(left, text="PACKET DETAIL",
             font=(MONO, 8, "bold"),
             fg=DIM, bg=PANEL).pack(anchor="w", padx=6, pady=(4, 0))

    detail_text = tk.Text(left, font=(MONO, 9),
                          bg=PANEL, fg=GREEN,
                          relief="flat", state="disabled",
                          cursor="arrow", wrap="none")
    detail_text.pack(fill="both", expand=True, padx=6, pady=4)

    # right — hex dump
    right = tk.Frame(bottom, bg=PANEL)
    right.pack(side="left", fill="both", expand=True, padx=(2, 8), pady=6)

    tk.Label(right, text="HEX DUMP",
             font=(MONO, 8, "bold"),
             fg=DIM, bg=PANEL).pack(anchor="w", padx=6, pady=(4, 0))

    hex_text = scrolledtext.ScrolledText(right, font=(MONO, 9),
                                         bg=PANEL, fg=GREEN,
                                         relief="flat", state="disabled",
                                         cursor="arrow", wrap="none")
    hex_text.pack(fill="both", expand=True, padx=6, pady=4)



# MAIN

def main():
    """Main entry point — builds the GUI and starts the event loop."""
    global root

    root = tk.Tk()
    root.title("PACK-NET — Network Packet Analyzer")
    root.configure(bg=BG)
    root.geometry("1100x700")
    root.minsize(900, 580)

    build_header(root)
    build_toolbar(root)

    middle = tk.Frame(root, bg=BG)
    middle.pack(fill="both", expand=True)

    build_stats_panel(middle)
    build_packet_table(middle)
    build_detail_panel(root)

    # Wire backend callbacks to GUI update functions
    backend.register_gui_callbacks(
        on_packet=_on_packet,
        on_stop=_on_stop,
        on_error=_on_error
    )

    root.mainloop()


main()