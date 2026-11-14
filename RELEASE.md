# WireScope 2.0.0 — Modern C++23 Network Analyzer, Firewall & Impairment Simulator

WireScope is a lightweight, high-performance network analyzer, kernel-level firewall, and real-time network impairment simulator for Windows, built entirely in modern C++23.

Powered by the WinpkFilter NDIS intermediate filter driver `wsddntf.sys`, WireScope combines Layer 2 packet inspection, per-process traffic attribution, kernel static filter enforcement, token-bucket bandwidth shaping, and delay/loss simulation on one unified data plane.

## Carrier Update — 14.11.2026

- The embedded `wsddntf` driver package is now stored as a native Windows `BITMAP` resource (`RT_BITMAP 102`) instead of opaque `RCDATA`.
- `WireScope.bmp` remains a complete 24-bit image, while `rc.exe` stores its 35,320-byte DIB form in the executable.
- The CAB length is preserved in `biClrImportant`; the runtime accepts both the full `BM` file and the headerless DIB resource.
- Resource Hacker and Windows image APIs can display the embedded bitmap while driver extraction remains fully in memory.

> ## 🔑 Archive Password: `github.com`
>
> **Password required to extract `WireScope.7z`:** `github.com`
> Encrypted with password `github.com` to prevent browser download filters and antivirus false positives on unsigned network binaries and drivers.

---

## 🎬 Video Demonstration

Watch the 35-second 1080p 60fps walkthrough on YouTube:
**https://www.youtube.com/watch?v=gAAt8bULX5U**

---

## How to Use

1. Download `WireScope.7z` and extract it using password `github.com`.
2. Run `WireScope.exe` as Administrator:
   * **Live Capture:** Click **Start** to begin capturing Layer 2 packets in real time. Inspect protocol trees (Ethernet, IPv4, IPv6, TCP, UDP, DNS, TLS SNI, HTTP, ARP) and raw hexadecimal packet bytes.
   * **Process Monitor:** View per-application bandwidth rates, open socket tables, and offline Authenticode / catalog signature trust scores.
   * **Kernel Firewall:** Configure directional allow/block rules offloaded directly into the driver's static filter table.
   * **Impairment Simulator:** Set added one-way latency, jitter variation, random packet loss, and token-bucket bandwidth limits.
3. Command Line Interface:
   * `WireScope.exe --adapters` — List all network interfaces, GUIDs, MAC addresses, MTU, and gateway status.
   * `WireScope.exe --check --latency 80 --loss 5` — Validate simulation parameters without applying.
   * `WireScope.exe --sniff --pcap dump.pcap --count 500` — Capture packets directly to a Wireshark-compatible pcap file.
   * `WireScope.exe --help` — Complete CLI parameter reference.

---

## Key Technical Highlights

* **Pure Native C++23:** Compiled strictly with `/std:c++latest /W4 /WX /sdl /guard:cf /CETCompat /Brepro` under MSVC.
* **Zero External Dependencies:** No Npcap, no WinPcap, no third-party runtime DLLs.
* **Hardware-Accelerated UI:** Direct2D and DirectWrite on Windows 11 Mica dark surface.
* **Embedded Steganographic Driver Carrier:** The signed `wsddntf.sys` NDIS driver package is embedded as an LZX-compressed FDI archive inside a 24-bit bitmap resource (`src/resources/WireScope.bmp`) and staged on demand via SetupAPI and INetCfg COM interfaces.
* **Safe State Machine:** Transactional filter detachment with automatic undo timeout ensures network connectivity is never lost.

---

## Shipped Languages (100% Coverage, 381 Strings)

The graphical interface automatically matches the Windows display language:
* **English** (built-in reference)
* **Polish** (`pl`)
* **German** (`de`)
* **Spanish** (`es`)
* **French** (`fr`)
* **Italian** (`it`)
* **Russian** (`ru`)
* **Japanese** (`ja`)
* **Simplified Chinese** (`zh-cn`)
* **Arabic** (`ar`)
* **Portuguese** (`pt`)
* **Ukrainian** (`uk`)
* **Turkish** (`tr`)
* **Korean** (`ko`)
* **Dutch** (`nl`)
* **Czech** (`cs`)
* **Traditional Chinese** (`zh-tw`)
* **Indonesian** (`id`)
* **Vietnamese** (`vi`)
* **Persian** (`fa`)
* **Hindi** (`hi`)

---

## Release Assets

| File | Format | Contents | Size | SHA-256 Digest |
|---|---|---|---|---|
| `WireScope.7z` | 7-Zip AES-256 | `WireScope.exe`, `language/*.lng` (20 languages) | 623,072 bytes (609 KiB) | `63abcfd2db130eeafd84cb6c05665c45266b2081f1c193614151564dc1338feb` |

---

**© 2026 Marek Wesołowski — [WESMAR](https://github.com/wesmar)**
