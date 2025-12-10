# Base Image: Lightweight Python 3.10
FROM python:3.10-slim-buster

# Metadata
LABEL name="BREAKPOINT"
LABEL version="2.0.0-ELITE"
LABEL description="Weaponized Audit Engine Container"
LABEL maintainer="BREAKPOINT Team"

# Environment Setup
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV WORKDIR=/app

# Create Directory
WORKDIR $WORKDIR

# Install System Dependencies (for aggressive networking/lxml)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc-dev \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Source Code
COPY breakpoint/ ./breakpoint/
COPY examples/ ./examples/

# Create a non-root user for security (Irony: Using a secure container to break things)
RUN useradd -m auditor
USER auditor

# Entry Point
ENTRYPOINT ["python", "-m", "breakpoint"]
CMD ["--help"]
