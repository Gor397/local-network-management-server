FROM python:3.12-slim AS wheels
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY backend/requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data
RUN groupadd --gid 10001 lantern && useradd --uid 10001 --gid lantern --no-create-home lantern
COPY --from=wheels /wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r /tmp/requirements.txt && rm -rf /wheels /tmp/requirements.txt
WORKDIR /app
COPY --chown=lantern:lantern backend/ /app/
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers", "--limit-concurrency", "64"]
