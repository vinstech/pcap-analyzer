# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PCAP Analyzer is a web-based network packet capture analysis tool with three specialized views:
- **SIP Ladder Diagrams** — Interactive SVG sequence diagrams of SIP call flows with Call-ID filtering
- **T.38 Fax Viewer** — T.38 fax session detection with packet statistics and TIFF extraction attempts
- **TLS Handshake Inspector** — Per-stream TLS negotiation details (version, cipher suites, certificate chains)

## Running the Application

```bash
# Build and run with Docker
docker compose up --build

# Access at http://localhost:5000
```

The upload directory `/tmp/pcap_uploads` is bind-mounted via Docker Compose, so you can drop `.pcap`/`.pcapng`/`.cap` files there directly. Each upload overwrites `capture.pcap` — there is no persistence across uploads.

There is no test suite.

## Architecture

```
backend/
  app.py           — Flask app; two routes: POST /api/upload, GET /api/cert/<stream_index>
  pcap_parser.py   — PcapParser class; all analysis logic
  requirements.txt — flask, flask-cors only

frontend/
  templates/
    index.html     — Entire SPA: embedded CSS, HTML, ~400 lines of vanilla JS
```

### Data Flow

1. Browser uploads PCAP → `POST /api/upload`
2. `app.py` saves file to `/tmp/pcap_uploads/capture.pcap` and calls `PcapParser.parse_all()`
3. `PcapParser` runs `tshark` subprocesses (with `-T fields`) for each protocol: SIP, T.38, TLS, summary
4. Parsed JSON returned to browser
5. Frontend renders SVG ladder (SIP), session cards (T.38/TLS)

### Backend: PcapParser

All parsing funnels through `run_tshark(args)` which executes tshark with field extraction. Key methods:
- `parse_sip()` — Groups messages by Call-ID, builds ordered endpoint list for the ladder
- `parse_t38()` — Detects fax sessions; `_extract_t38_tiff()` attempts tshark IMF object export (incomplete by design)
- `parse_tls()` — Maps TLS versions/ciphers per stream; `_extract_certs_for_stream()` / `get_cert_detail()` convert tshark hex output to PEM and parse via `openssl` subprocess
- `parse_summary()` — Packet count and protocol breakdown

Certificate detail is fetched lazily: clicking a cert in the UI triggers `GET /api/cert/<stream_index>`.

### Frontend

Single file (`index.html`) with no build step. Key globals and functions:
- `pcapData` / `sipData` — global state holding parsed JSON
- `renderLadder()` — Generates SVG; arrows color-coded (2xx=green, 4xx/5xx=red, requests=cyan)
- `initSIP()`, `initT38()`, `initTLS()` — Populate their respective panels
- `showCert()` / `renderCertModal()` — Lazy-fetch and display certificate chains
- `escXml()` / `escHtml()` — Output escaping (important: always use these when inserting user/network data into the DOM or SVG)

## Key Dependencies

- **tshark** (Wireshark CLI) — required at runtime; all packet parsing delegates to it
- **openssl** — used to parse certificate PEM output from tshark
- Both are installed in the Docker image; the app will not work without them
