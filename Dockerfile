# Sniper Security Scanner Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.10-slim as builder

WORKDIR /app

# Install system dependencies required for some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==1.6.1

# Copy only requirements files to cache dependencies
COPY pyproject.toml poetry.lock* ./

# Configure poetry to not use a virtual environment in the container
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-interaction --no-ansi --no-dev

# Runtime stage
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry==1.6.1

# Copy project files
COPY pyproject.toml poetry.lock* ./
COPY README.md ./

# Configure poetry to not use a virtual environment
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-interaction --no-ansi --no-dev

# Copy the rest of the application
COPY . .

# Create necessary directories
RUN mkdir -p /app/data/reports /app/data/models /app/config

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Create a non-root user to run the application
RUN groupadd -r sniper && \
    useradd -r -g sniper -d /app -s /bin/bash sniper && \
    chown -R sniper:sniper /app

# Switch to non-root user
USER sniper

# Create volume mount points
VOLUME ["/data/reports", "/data/models", "/config"]

# Set entrypoint and default command
ENTRYPOINT ["python", "-m", "src.cli.scan", "--help"]
CMD ["--help"] 