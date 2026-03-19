# PCAP Analyzer

A web-based network capture analysis tool with three views:

- **SIP Ladder Diagram** — interactive SVG sequence diagram of SIP call flows, filterable by Call-ID. Click any message to see the full SIP payload.
- **T.38 Fax Viewer** — detects T.38/UDPTL fax sessions, shows per-packet breakdown, and attempts to reconstruct fax pages as TIFF images (non-ECM and ECM modes).
- **TLS Handshake Inspector** — per-stream TLS negotiation details including version, cipher suite, and full certificate chain (parsed text + PEM).

All three views show frame numbers you can cross-reference directly in Wireshark.

## Pull and run (pre-built image)

```bash
# Pull the image
docker pull ghcr.io/kvarughese/pcap-analyzer:latest

# Run (creates a ./captures folder you can drop .pcap files into)
docker run -d \
  --name pcap-analyzer \
  -p 5000:5000 \
  -v "$(pwd)/captures:/tmp/pcap_uploads" \
  ghcr.io/kvarughese/pcap-analyzer:latest
```

Or with Docker Compose:

```bash
curl -O https://raw.githubusercontent.com/kvarughese/pcap-analyzer/main/docker-compose.yml
docker compose up -d
```

Then open **http://localhost:5000**.

## Build from source

```bash
git clone https://github.com/kvarughese/pcap-analyzer.git
cd pcap-analyzer
docker compose up --build
```

## Usage

1. Open `http://localhost:5000`
2. Drag & drop or click to upload a `.pcap`, `.pcapng`, or `.cap` file
3. Switch between tabs:
   - **SIP Ladder** — filter by Call-ID; arrows are colour-coded (green = 2xx, red = 4xx/5xx/BYE, blue = other requests). Click any row to see the raw SIP message.
   - **T.38 Fax** — sessions detected automatically; fax image rendered inline when data is available. Use the built-in diagnostics panel if no image appears.
   - **TLS Handshakes** — expand a stream to see each handshake step with frame numbers. Click **View Certificate** to inspect the cert chain.

## Requirements

- Docker (no other dependencies)
- PCAP files only — no live capture

## Architecture

```
pcap-analyzer/
├── backend/
│   ├── app.py           # Flask API (upload, cert, SIP frame, T.38 debug)
│   ├── pcap_parser.py   # All parsing via tshark subprocesses
│   └── requirements.txt
├── frontend/
│   └── templates/
│       └── index.html   # Single-file SPA (vanilla JS, no build step)
├── Dockerfile
└── docker-compose.yml
```

All parsing runs server-side via `tshark`. Uploads are stored at `/tmp/pcap_uploads/capture.pcap` and overwritten on each new upload — nothing is persisted across container restarts.
