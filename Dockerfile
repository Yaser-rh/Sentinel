FROM python:3.11-slim

# System dependencies for Trivy + Semgrep
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (Linux binary)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Python dependencies first (layer caching)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Semgrep via pip (works natively on Linux)
RUN pip install --no-cache-dir semgrep

# Copy project and install Sentinel
COPY . .
RUN pip install --no-cache-dir -e .

# The user mounts their project to scan here
VOLUME /project
WORKDIR /project

ENTRYPOINT ["sentinel"]
CMD ["--help"]
