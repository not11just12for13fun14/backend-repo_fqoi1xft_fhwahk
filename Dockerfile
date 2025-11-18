# flames.blue honeypot container
FROM python:3.11-slim

# Create non-root user
RUN useradd -m -u 10001 honeypot

# Minimal OS packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Directories with restricted perms
RUN mkdir -p /opt/honeypot/quarantine /var/log/honeypot && \
    chown -R honeypot:honeypot /opt/honeypot /var/log/honeypot && \
    chmod 750 /opt/honeypot /var/log/honeypot

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application
COPY honeypot_app.py /app/honeypot_app.py
COPY templates /app/templates

# Drop privileges
USER honeypot

ENV PORT=8080 \
    PYTHONUNBUFFERED=1 \
    SYSLOG_TARGET=

EXPOSE 8080

# Use gunicorn for production serving
CMD ["gunicorn", "-b", "0.0.0.0:8080", "honeypot_app:app", "--workers", "2", "--threads", "4"]
