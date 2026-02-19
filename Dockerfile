# AtilKurt - Active Directory Security Health Check Tool
# Multi-stage optional: use python:3.11-slim for smaller image

FROM python:3.11-slim

LABEL maintainer="cumakurt@gmail.com"
LABEL description="AtilKurt - AD Security Health Check (read-only LDAP)"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install only runtime deps if needed (ldap3 is pure Python)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency file first for layer cache
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY AtilKurt.py .
COPY core/ ./core/
COPY analysis/ ./analysis/
COPY reporting/ ./reporting/
COPY scoring/ ./scoring/
COPY risk/ ./risk/

# Output directory for reports (mount as volume)
RUN mkdir -p /output

# Entrypoint: if env vars set, run with them; else exec args as-is
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["--help"]
