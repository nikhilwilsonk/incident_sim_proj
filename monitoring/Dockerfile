FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/monitoring
RUN mkdir -p /app

COPY monitor.py /app/
COPY requirements.txt /app/
COPY utils.py /app/

WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Set permissions
RUN chmod +x /app/monitor.py

CMD ["python", "/app/monitor.py"]