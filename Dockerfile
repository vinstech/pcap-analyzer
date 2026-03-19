FROM python:3.12-slim

# Install tshark and openssl (required at runtime for packet parsing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    openssl \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Allow tshark to read capture files without root
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap 2>/dev/null || true

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN mkdir -p /tmp/pcap_uploads

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "backend/app.py"]
