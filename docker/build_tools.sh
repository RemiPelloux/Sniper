#!/bin/bash

# Script to build security tool Docker images for Sniper

set -e  # Exit on any error

echo "Building Sniper security tool Docker images..."

# Go to script directory
cd "$(dirname "$0")"

# Build individual tool images
echo "Building dirsearch image..."
docker build -t sniper/dirsearch:latest ./dirsearch

echo "Building subfinder image..."
docker build -t sniper/subfinder:latest ./subfinder

echo "All tool images built successfully!"

# Instructions for running individual tools
echo ""
echo "To run dirsearch:"
echo "  docker run --rm -it sniper/dirsearch:latest -u https://example.com -e php,html,js"
echo ""
echo "To run subfinder:"
echo "  docker run --rm -it sniper/subfinder:latest -d example.com"
echo ""
echo "Alternative: Use docker-compose to manage all tools:"
echo "  docker compose -f docker-compose.tools.yml up dirsearch"
echo "  docker compose -f docker-compose.tools.yml up subfinder" 