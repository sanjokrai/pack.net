# 📡 PACK-NET — Network Packet Analyser

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![License](https://img.shields.io/badge/License-Educational-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

PACK-NET is a real-time network packet analyser built with Python. It captures live network traffic using Scapy and displays packets in a colour-coded graphical interface built with tkinter. Developed as an educational tool, PACK-NET demonstrates how packets travel across networks and how sensitive data can be exposed over unencrypted connections.



## ✨ Features

- 🔴 **Live packet capture** — captures TCP, UDP, and ICMP packets in real time
- 🎨 **Colour-coded table** — instantly distinguish protocols at a glance
- 🔍 **Hex dump inspector** — view raw bytes and ASCII characters of any packet
- 📊 **Live statistics sidebar** — real-time counters and protocol bar chart
- 🔎 **Protocol filtering** — filter by TCP, UDP, ICMP, or OTHER at any time
- 🧵 **Background threading** — capture runs in a daemon thread so the GUI stays responsive
- 🗂️ **Parallel list storage** — custom data structure without relying on built-in dictionaries or classes

---

## 🗂️ Project Structure

```
pack.net/
│
├── backend.py          # Packet capture, processing, storage, and hex dump logic
├── frontend.py         # tkinter GUI — table, toolbar, stats panel, hex dump view
├── test_pack_net.py    # Unit tests for all backend functions (17 tests)
└── README.md
```

---

## 🛠️ Requirements

- Python 3.x
- [Scapy](https://scapy.readthedocs.io/)

Install Scapy with:

```bash
pip3 install scapy
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/sanjokrai/pack.net.git
cd pack.net
```

### 2. Run the application

> ⚠️ **Administrator/root privileges are required** to capture raw network traffic.

**Windows (run as Administrator):**
```bash
python frontend.py
```

**Linux / macOS:**
```bash
sudo python3 frontend.py
```

### 3. Using PACK-NET

1. Select your **network interface** from the toolbar (e.g., `eth0`, `Wi-Fi`)
2. Set an optional **packet limit** (leave blank for unlimited)
3. Click **▶ START** to begin capturing
4. Click any row in the table to view the **full packet details and hex dump**
5. Use the **filter dropdown** to show only TCP, UDP, ICMP, or OTHER packets
6. Click **■ STOP** to end the session

---

## 🧪 Running Unit Tests

```bash
python3 test_pack_net.py
```

17 tests cover the four core backend functions:

| Function | Tests | Coverage |
|---|---|---|
| `get_protocol_name()` | 4 | Protocol number → name mapping |
| `store_packet()` | 4 | Parallel list storage and sync |
| `clear_data()` | 2 | Full reset of lists and counters |
| `format_hex_dump()` | 7 | Offsets, hex values, ASCII rendering |

---

## 🏗️ How It Works

PACK-NET processes packets in five stages:

```
Capture → Store → Process → Display → Interface
```

1. **Capture** — Scapy's `sniff()` listens on the selected interface in promiscuous mode
2. **Store** — Packet fields are saved into eight parallel lists (timestamp, src IP, dst IP, protocol, src port, dst port, size, raw bytes)
3. **Process** — Protocol number is mapped to a name; ports are extracted per protocol
4. **Display** — Rows are added to the tkinter Treeview table; hex dump is rendered on row click
5. **Interface** — The GUI toolbar gives full control; stats sidebar updates after every packet

---

## ⚖️ Legal and Ethical Notice

> **PACK-NET is strictly for educational use on authorised networks only.**

Unauthorised packet sniffing is a criminal offence under:
- 🇬🇧 **Computer Misuse Act 1990** (United Kingdom)
- 🇳🇵 **Electronic Transactions Act 2063** (Nepal)
- 🇳🇵 **Privacy Act 2075** (Nepal)

Always obtain explicit permission before capturing traffic on any network you do not own.

---

## 🧰 Built With

| Tool | Purpose |
|---|---|
| Python 3 | Core programming language |
| Scapy | Low-level packet capture |
| tkinter | Graphical user interface |
| threading | Background capture thread |
| datetime | Packet timestamping |
| Visual Studio Code | Development environment |
| GitHub | Version control |

---

## 👨‍💻 Author

**Sanjok Rai**  
BSc (Hons) Ethical Hacking and Cybersecurity  
Coventry University  
Student ID: 254450

---