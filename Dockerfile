FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user and setup data directory
RUN useradd -m appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

# Environment variables should be passed at runtime
# ENV MISP_URL=""
# ENV MISP_API_KEY=""

# Create a volume for state persistence if not using docker-compose volumes
# VOLUME /app/state

CMD ["python", "-m", "src.main"]
