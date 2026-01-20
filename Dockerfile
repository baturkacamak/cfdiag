# Use a lightweight Python base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies required by cfdiag
# dnsutils -> dig
# netcat-openbsd -> nc
# iputils-ping -> ping
# traceroute -> traceroute
# curl -> curl
# openssl -> openssl
RUN apt-get update && apt-get install -y \
    curl \
    dnsutils \
    netcat-openbsd \
    iputils-ping \
    traceroute \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy script
COPY cfdiag.py .

# Entrypoint allows arguments to be passed directly
ENTRYPOINT ["python3", "cfdiag.py"]

