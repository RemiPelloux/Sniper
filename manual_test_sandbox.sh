#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print section headers
print_section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# Function to check command status
check_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ Success${NC}"
    else
        echo -e "${RED}✗ Failed with exit code $1${NC}"
        if [ "$2" == "exit" ]; then
            exit 1
        fi
    fi
}

# Ensure we're in the correct directory
cd "$(dirname "$0")"
SNIPER_DIR="$PWD"
echo "Running from directory: $SNIPER_DIR"

# Check Docker is running
print_section "Checking Docker is running"
docker info > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
else
    echo -e "${GREEN}Docker is running.${NC}"
fi

# Test 1: List available sandbox environments
print_section "Testing 'sniper sandbox list' command"
poetry run sniper sandbox list
check_status $?

# Test 2: Starting DVWA sandbox environment
print_section "Testing 'sniper sandbox start dvwa' command"
poetry run sniper sandbox start dvwa
check_status $?

# Wait a moment for container to start
echo "Waiting 5 seconds for container to initialize..."
sleep 5

# Test 3: Check status of DVWA environment
print_section "Testing 'sniper sandbox status dvwa' command"
poetry run sniper sandbox status dvwa
check_status $?

# Extract access URL for web access testing
ACCESS_URL=$(poetry run sniper sandbox status dvwa | grep http | awk '{print $3}')
if [ -n "$ACCESS_URL" ]; then
    echo -e "Access URL detected: ${GREEN}$ACCESS_URL${NC}"
    
    # Optional: Check if the URL is accessible (requires curl)
    if command -v curl &> /dev/null; then
        echo "Testing HTTP accessibility with curl..."
        curl -sL --head "$ACCESS_URL" > /dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}URL is accessible!${NC}"
        else
            echo -e "${RED}URL is not accessible. Container may not be fully started.${NC}"
        fi
    fi
else
    echo -e "${RED}Could not detect access URL from status output.${NC}"
fi

# Test 4: Stop DVWA environment
print_section "Testing 'sniper sandbox stop dvwa' command"
poetry run sniper sandbox stop dvwa
check_status $?

# Test 5: Start Juice Shop sandbox environment
print_section "Testing 'sniper sandbox start juiceshop' command"
poetry run sniper sandbox start juiceshop
check_status $?

# Wait a moment for container to start
echo "Waiting 5 seconds for container to initialize..."
sleep 5

# Test 6: Check status of Juice Shop environment
print_section "Testing 'sniper sandbox status juiceshop' command"
poetry run sniper sandbox status juiceshop
check_status $?

# Extract access URL for web access testing
ACCESS_URL=$(poetry run sniper sandbox status juiceshop | grep http | awk '{print $3}')
if [ -n "$ACCESS_URL" ]; then
    echo -e "Access URL detected: ${GREEN}$ACCESS_URL${NC}"
    
    # Optional: Check if the URL is accessible (requires curl)
    if command -v curl &> /dev/null; then
        echo "Testing HTTP accessibility with curl..."
        curl -sL --head "$ACCESS_URL" > /dev/null
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}URL is accessible!${NC}"
        else
            echo -e "${RED}URL is not accessible. Container may not be fully started.${NC}"
        fi
    fi
else
    echo -e "${RED}Could not detect access URL from status output.${NC}"
fi

# Test 7: Stop Juice Shop environment
print_section "Testing 'sniper sandbox stop juiceshop' command"
poetry run sniper sandbox stop juiceshop
check_status $?

# Test 8: Attempt to start non-existent environment (negative test)
print_section "Testing starting non-existent environment (should fail)"
poetry run sniper sandbox start nonexistent 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${GREEN}✓ Test passed: Command failed as expected${NC}"
else
    echo -e "${RED}✗ Test failed: Command succeeded but should have failed${NC}"
fi

# Final summary
print_section "Test Summary"
echo -e "${GREEN}Sandbox manual testing completed.${NC}"
echo "Please review the output above for any errors." 