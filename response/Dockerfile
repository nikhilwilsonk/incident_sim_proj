FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/response
RUN mkdir -p /var/reports
RUN mkdir -p /app

COPY responder.py /app/
COPY requirements.txt /app/
COPY report_template.html /app/
COPY utils.py /app/

WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x /app/responder.py

CMD ["python", "/app/responder.py"]