FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home sentinel
COPY sentinel/ ./sentinel/
COPY --from=frontend /build/dist ./frontend/dist/
RUN mkdir /data && chown sentinel:sentinel /data
USER sentinel
ENV SENTINEL_DB=/data/sentinel.db PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "sentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
