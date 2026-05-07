FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api /app/api
COPY worker /app/worker

CMD ["celery", "-A", "worker.app.celery_app.celery_app", "worker", "--loglevel=INFO"]

