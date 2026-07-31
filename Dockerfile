FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY relay.py .
COPY templates/ ./templates/
COPY static/ ./static/

# Run as an unprivileged user. UID/GID 1000 matches the typical first
# host user so the bind-mounted ./data volume stays writable.
RUN groupadd -g 1000 relay && useradd -u 1000 -g relay -M relay \
    && mkdir -p /data && chown relay:relay /data /app
USER relay

EXPOSE 8000

# 2 workers is plenty — sends are short-lived and low-volume. The long
# timeout tolerates slow upstream SMTP servers without killing a worker
# mid-delivery.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "--timeout", "120", "relay:app"]
