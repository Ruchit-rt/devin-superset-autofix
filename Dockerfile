FROM python:3.11-slim

# osv-scanner (bundled so `docker compose up` can do real scans out of the box)
ARG TARGETARCH=amd64
ARG OSV_VERSION=1.9.2
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL -o /usr/local/bin/osv-scanner \
       "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OSV_VERSION}_linux_${TARGETARCH}" \
    && chmod +x /usr/local/bin/osv-scanner

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8080
CMD ["python", "app.py"]
