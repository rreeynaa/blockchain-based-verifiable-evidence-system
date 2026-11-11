# syntax=docker/dockerfile:1
# One Dockerfile, two images: api/ingestor use requirements-api.txt, ui uses requirements-ui.txt.
FROM python:3.11-slim
ARG REQUIREMENTS=requirements-api.txt
# Override on slow/blocked networks, e.g. --build-arg PIP_INDEX_URL=https://<mirror>/simple
ARG PIP_INDEX_URL=https://pypi.org/simple
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10 PIP_INDEX_URL=${PIP_INDEX_URL}
WORKDIR /app
COPY ${REQUIREMENTS} ./requirements.txt
# The cache mount keeps downloaded wheels between attempts, so a retry after a timeout resumes cheaply.
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt
COPY . .
