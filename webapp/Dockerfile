FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/webapp

WORKDIR /app

COPY requirements.txt .
COPY utils.py .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

ENV PYTHONUNBUFFERED=1

EXPOSE 80

CMD ["python", "app.py"]