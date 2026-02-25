# NetSentinel

> A modern C++17 Deep Packet Inspection engine built for education and experimentation.

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg?style=flat-square)](https://en.cppreference.com/w/cpp/17)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey.svg?style=flat-square)]()

---

## Overview

**NetSentinel** is a from-scratch Deep Packet Inspection (DPI) engine designed to help developers, students, and networking enthusiasts understand how real-world traffic analysis systems work. It reads PCAP capture files, dissects each packet through protocol layers, classifies network flows by application, enforces configurable blocking policies, and produces filtered output.

> [!IMPORTANT]
> This is an **educational project**. It is not intended for production use, real-time packet filtering, or deployment on live networks. Use responsibly and only on traffic you are authorised to inspect.

---

## Architecture

```
┌───────────────────────────────────────────────────┐
│                  NetSentinel Pipeline              │
├───────────────────────────────────────────────────┤
│                                                   │
│  ┌─────────────┐                                  │
│  │ PcapIngester │  ← Read frames from .pcap file  │
│  └──────┬──────┘                                  │
│         │                                         │
│         ▼                                         │
│  ┌──────────────┐                                 │
│  │FrameDissector│  ← Parse Eth / IPv4 / TCP / UDP │
│  └──────┬───────┘                                 │
│         │                                         │
│         ▼                                         │
│  ┌──────────────┐                                 │
│  │SessionLedger │  ← Track flow state & lifecycle │
│  └──────┬───────┘                                 │
│         │                                         │
│         ▼                                         │
│  ┌───────────────────────────────┐                │
│  │ TlsProber + AppFingerprinter │ ← Classify app  │
│  └──────┬────────────────────────┘                │
│         │                                         │
│         ▼                                         │
│  ┌──────────────┐                                 │
│  │ PolicyEngine │  ← Enforce JSON blocking rules  │
│  └──────┬───────┘                                 │
│         │                                         │
│         ▼                                         │
│  ┌──────────────┐                                 │
│  │  PcapWriter  │  ← Write allowed packets out    │
│  └──────────────┘                                 │
│                                                   │
└───────────────────────────────────────────────────┘
```

### Module Map

| Module | Key Class | Responsibility |
|--------|-----------|----------------|
| `core/` | `FlowKey`, `SessionRecord`, `EngineMetrics` | Data types, protocol constants |
| `capture/` | `PcapIngester`, `FrameDissector` | PCAP I/O, protocol parsing |
| `flow/` | `SessionLedger`, `FlowOrchestrator` | Per-flow state machine, aggregation |
| `analysis/` | `TlsProber`, `AppFingerprinter` | TLS SNI extraction, app classification |
| `rules/` | `PolicyEngine` | JSON-configurable IP/app/domain/port blocking |
| `engine/` | `InspectionPipeline` | Top-level orchestrator |
| `benchmark/` | `Stopwatch` | Per-stage performance timing |

---

## Features

- **Multi-layer dissection** — Ethernet → IPv4 → TCP / UDP with bounds-checked parsing
- **TLS SNI extraction** — Inspects ClientHello messages to identify HTTPS hostnames
- **Application fingerprinting** — Maps 25+ services (Google, YouTube, Netflix, Discord, etc.)
- **Flow lifecycle tracking** — `Initiated → Handshake → Active → Classified → Terminated`
- **JSON-based rule engine** — Block by IP, application, domain (wildcards), or port
- **Performance benchmarking** — Per-stage timing with formatted reports
- **PCAP in / PCAP out** — Non-destructive filtering: only allowed packets are written
- **Clean C++17 codebase** — `std::optional`, `std::string_view`, `[[nodiscard]]`, RAII

---

## Getting Started

### Prerequisites

- **CMake** ≥ 3.16
- **C++17** compiler (Clang 10+, GCC 9+, MSVC 2019+)
- macOS or Linux (tested on macOS Ventura and Ubuntu 22.04)

### Build

```bash
git clone https://github.com/bibekthakur/NetSentinel.git
cd NetSentinel
mkdir build && cd build
cmake ..
make -j$(nproc)    # Linux
# or
make -j$(sysctl -n hw.ncpu)   # macOS
```

### Run

```bash
# Basic usage
./net_sentinel --input ../test_dpi.pcap --output filtered.pcap

# With JSON rules and verbose logging
./net_sentinel --input ../test_dpi.pcap --output filtered.pcap \
               --rules ../rules.json --verbose

# With performance benchmarking
./net_sentinel --input ../test_dpi.pcap --output filtered.pcap \
               --rules ../rules.json --benchmark
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--input <file>` | **(Required)** Input PCAP file |
| `--output <file>` | **(Required)** Output PCAP file for forwarded packets |
| `--rules <file>` | JSON rules file for blocking policies |
| `--verbose` | Print per-packet classification and drop details |
| `--benchmark` | Print per-stage performance timing breakdown |
| `--help` | Show usage information |

---

## Rules Configuration

Create a `rules.json` file to define blocking policies:

```json
{
  "blocked_ips": ["192.168.1.100", "10.0.0.50"],
  "blocked_apps": ["TikTok", "Instagram"],
  "blocked_domains": [
    "malware.example.com",
    "*.phishing-site.net",
    "*.tracking.com"
  ],
  "blocked_ports": [8888, 9999]
}
```

### Supported App Names

`HTTP`, `HTTPS`, `DNS`, `TLS`, `QUIC`, `Google`, `Facebook`, `YouTube`, `Twitter`, `Instagram`, `Netflix`, `Amazon`, `Microsoft`, `Apple`, `WhatsApp`, `Telegram`, `TikTok`, `Spotify`, `Zoom`, `Discord`, `GitHub`, `Cloudflare`, `Reddit`, `LinkedIn`

---

## Sample Output

```
  ┌─────────────────────────────────────────┐
  │  ░█▄░█ █▀▀ ▀█▀ ░ █▀ █▀▀ █▄░█ ▀█▀ █   │
  │  ░█░▀█ ██▄ ░█░ ░ ▄█ ██▄ █░▀█ ░█░ █▄▄ │
  │       Deep Packet Inspection Engine     │
  │             v1.0.0 — 2026               │
  └─────────────────────────────────────────┘

╔══════════════════════════════════════════╗
║        NetSentinel Engine Report         ║
╠══════════════════════════════════════════╣
║  Total Packets      :                42 ║
║  Total Bytes        :              6994 ║
║  Forwarded          :                38 ║
║  Dropped            :                 4 ║
║  TCP Packets        :                30 ║
║  UDP Packets        :                12 ║
╚══════════════════════════════════════════╝

╔══════════════════════════════════════════╗
║       Performance Benchmark Report       ║
╠══════════════════════════════════════════╣
║  Dissect            :      0.234 ms ... ║
║  FlowTrack          :      0.089 ms ... ║
║  Classify           :      0.156 ms ... ║
║  Enforce            :      0.023 ms ... ║
║  Output             :      0.045 ms ... ║
╚══════════════════════════════════════════╝
```

---

## Project Structure

```
NetSentinel/
├── CMakeLists.txt
├── README.md
├── rules.json
├── include/sentinel/
│   ├── core/          ← Protocol constants & data types
│   ├── capture/       ← PCAP I/O & frame dissection
│   ├── flow/          ← Session tracking & orchestration
│   ├── analysis/      ← TLS probing & app fingerprinting
│   ├── rules/         ← JSON policy engine
│   ├── engine/        ← Top-level pipeline
│   └── benchmark/     ← Performance timing
├── src/               ← Implementation files (mirrors include/)
└── test_dpi.pcap      ← Sample capture for testing
```

---

## Design Principles

- **Separation of concerns** — Each module has a single, well-defined responsibility
- **Modern C++17** — RAII, `std::optional`, `std::string_view`, `[[nodiscard]]`
- **No external runtime dependencies** — Only the C++ standard library
- **Configurable via JSON** — Rules can be changed without recompilation
- **Observable** — Built-in benchmarking and structured reporting
- **Extensible** — Add new protocol analysers or app signatures by editing one file

---

## Contributing

This is an educational project and contributions are welcome! Ideas for extension:

- IPv6 support
- QUIC/HTTP3 dissection
- Real-time capture via `libpcap`
- Multi-threaded pipeline with lock-free queues
- Web-based dashboard for live statistics
- YAML or TOML rule format support

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Author

**Bibek Thakur**

Built as an educational deep-dive into networking systems, protocol analysis, and modern C++ software architecture.

---

> *"The best way to understand a network is to watch the packets flow."*
