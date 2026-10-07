FROM python:3.12-slim

WORKDIR /app

# System dependencies for psycopg (if needed depending on the python slim variant)
RUN apt-get update && apt-get install -y libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Environment defaults
ENV APP_ENV=production
ENV PYTHONPATH=/app

# Run Alembic migrations and then start the server
CMD alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000
