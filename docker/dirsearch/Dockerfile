FROM python:3.10-slim

WORKDIR /tools

# Install git and requirements
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Clone dirsearch repository
RUN git clone https://github.com/maurosoria/dirsearch.git && \
    cd dirsearch && \
    pip install --no-cache-dir -r requirements.txt

# Create a symlink to make dirsearch available in PATH
RUN ln -s /tools/dirsearch/dirsearch.py /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/dirsearch

# Set working directory to dirsearch
WORKDIR /tools/dirsearch

# Set entrypoint to run dirsearch
ENTRYPOINT ["python3", "dirsearch.py"]

# Default command shows help
CMD ["--help"] 