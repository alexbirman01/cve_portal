# Stage 1 — build React
FROM node:22-alpine AS ui-build
WORKDIR /app
COPY ui/package*.json /app/
RUN npm ci
COPY ui /app
RUN npm run build

# Stage 2 — Python API + React dist/
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG GIT_COMMIT=unknown
ARG APP_VERSION=dev
ENV GIT_COMMIT=${GIT_COMMIT}
ENV APP_VERSION=${APP_VERSION}

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api /app/api
COPY worker /app/worker
COPY VERSION /app/VERSION
COPY --from=ui-build /app/dist /app/dist

EXPOSE 8000
CMD ["uvicorn", "api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
