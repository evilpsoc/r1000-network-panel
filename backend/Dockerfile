FROM node:18-bookworm-slim AS frontend

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    modemmanager \
    procps \
    nftables \
    samba-common-bin \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=frontend /frontend/dist ./frontend-dist
COPY backend/scripts/service-lan-ra.py /usr/local/bin/service-lan-ra.py
COPY backend/scripts/service-lan-inet-on.sh /usr/local/bin/service-lan-inet-on.sh
COPY backend/scripts/service-lan-inet-off.sh /usr/local/bin/service-lan-inet-off.sh
RUN chmod +x /usr/local/bin/service-lan-ra.py /usr/local/bin/service-lan-inet-on.sh /usr/local/bin/service-lan-inet-off.sh

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
