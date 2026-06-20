FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Production: NO --reload. (--reload restarts the worker on file changes or
# crashes the worker on a code error -> intermittent 502s.) Stable single worker.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
