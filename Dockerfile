FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy every module app.py imports (not just app.py) + the metrics capability catalog.
COPY app.py allowlist.py assessment.py findings_summary.py influx_backend.py \
     metrics_backend.py overview.py triage_tier.py ./
COPY metrics-capabilities.json ./
COPY static ./static
EXPOSE 8899
# Config is supplied via environment (see .env.example); pass with `--env-file .env`
# or a compose env_file. SOC_DB lives on a mounted volume at /data.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8899"]
