#!/bin/bash
# setup_sandbox_test.sh
# Script to set up a testing environment for Sniper sandbox commands

# Set text colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print heading
print_heading() {
    echo -e "\n${BLUE}==== $1 ====${NC}\n"
}

# Print success message
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Print error message
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Print warning message
print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Print info message
print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check requirements
check_requirements() {
    print_heading "Checking requirements"
    
    # Check if Docker is installed
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    else
        print_success "Docker is installed."
    fi
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    else
        print_success "Docker is running."
    fi
    
    # Check if docker-compose is installed
    if ! command_exists docker && ! command_exists docker-compose; then
        print_warning "Docker Compose not found as a standalone command. Assuming Docker Compose V2 is being used."
    else
        print_success "Docker Compose is available."
    fi
    
    # Check if Poetry is installed
    if ! command_exists poetry; then
        print_error "Poetry is not installed. Please install Poetry first."
        exit 1
    else
        print_success "Poetry is installed."
    fi
}

# Create test directory structure
create_test_directory() {
    print_heading "Creating test directory"
    
    # Get the project root (assuming script is run from project root)
    PROJECT_ROOT=$(pwd)
    
    # Create a sandbox_test directory
    TEST_DIR="$PROJECT_ROOT/sandbox_test"
    
    if [ -d "$TEST_DIR" ]; then
        print_warning "Sandbox test directory already exists at $TEST_DIR"
    else
        mkdir -p "$TEST_DIR"
        print_success "Created sandbox test directory at $TEST_DIR"
    fi
    
    # Create subdirectories for test data and evidence
    mkdir -p "$TEST_DIR/data"
    mkdir -p "$TEST_DIR/evidence"
    
    # Export the test directory as an environment variable
    export SNIPER_SANDBOX_TEST_DIR="$TEST_DIR"
    print_info "Set SNIPER_SANDBOX_TEST_DIR environment variable to $TEST_DIR"
}

# Verify Sniper installation
verify_sniper() {
    print_heading "Verifying Sniper installation"
    
    # Try to run a basic Sniper command
    if ! poetry run sniper --version >/dev/null 2>&1; then
        print_error "Sniper command failed. Make sure you're in the project root directory."
        exit 1
    else
        SNIPER_VERSION=$(poetry run sniper --version)
        print_success "Sniper is installed: $SNIPER_VERSION"
    fi
    
    # Check if sandbox plugin is available
    if ! poetry run sniper sandbox --help >/dev/null 2>&1; then
        print_error "Sandbox plugin does not appear to be available. Check if the plugin is loaded correctly."
        exit 1
    else
        print_success "Sandbox plugin is available."
    fi
}

# List available sandbox environments
list_sandbox_environments() {
    print_heading "Available sandbox environments"
    
    # Run the sandbox list command
    poetry run sniper sandbox list
    
    # Check if the command succeeded
    if [ $? -ne 0 ]; then
        print_error "Failed to list sandbox environments. There might be an issue with the sandbox plugin."
        exit 1
    fi
}

# Start sandbox environment(s)
start_sandbox_environments() {
    print_heading "Starting sandbox environments"
    
    # DVWA is a common and lightweight vulnerable web app
    print_info "Starting DVWA environment..."
    poetry run sniper sandbox start dvwa
    
    if [ $? -ne 0 ]; then
        print_error "Failed to start DVWA environment."
        print_warning "Continuing with other environments..."
    else
        print_success "DVWA environment started successfully."
    fi
    
    # Juice Shop is another popular vulnerable web app
    print_info "Starting Juice Shop environment..."
    poetry run sniper sandbox start juiceshop
    
    if [ $? -ne 0 ]; then
        print_error "Failed to start Juice Shop environment."
    else
        print_success "Juice Shop environment started successfully."
    fi
}

# Create a test script for manual testing
create_test_script() {
    print_heading "Creating test script"
    
    # Path to the test script
    TEST_SCRIPT="$SNIPER_SANDBOX_TEST_DIR/run_tests.sh"
    
    # Create a test script
    cat > "$TEST_SCRIPT" << 'EOF'
#!/bin/bash
# run_tests.sh - Manual test script for Sniper sandbox commands

# Test sandbox commands
echo "==== Testing 'sandbox status' command ===="
poetry run sniper sandbox status dvwa
poetry run sniper sandbox status juiceshop

echo "==== Testing scanning against sandbox environments ===="
# Get the URL from status output
DVWA_URL=$(poetry run sniper sandbox status dvwa | grep URL | awk '{print $2}')
if [ -n "$DVWA_URL" ]; then
    echo "Running a test scan against DVWA at $DVWA_URL"
    poetry run sniper scan web --target "$DVWA_URL" --output-format json --output sandbox_test/evidence/dvwa_scan.json
fi

JUICE_URL=$(poetry run sniper sandbox status juiceshop | grep URL | awk '{print $2}')
if [ -n "$JUICE_URL" ]; then
    echo "Running a test scan against Juice Shop at $JUICE_URL"
    poetry run sniper scan web --target "$JUICE_URL" --output-format json --output sandbox_test/evidence/juiceshop_scan.json
fi

echo "==== Testing 'sandbox stop' command ===="
poetry run sniper sandbox stop dvwa
poetry run sniper sandbox stop juiceshop

echo "Test script completed"
EOF
    
    # Make the test script executable
    chmod +x "$TEST_SCRIPT"
    
    print_success "Created test script at $TEST_SCRIPT"
    print_info "You can run manual tests using: ./sandbox_test/run_tests.sh"
}

# Main function
main() {
    print_heading "Sniper Sandbox Test Setup"
    
    check_requirements
    create_test_directory
    verify_sniper
    list_sandbox_environments
    start_sandbox_environments
    create_test_script
    
    print_heading "Setup Complete"
    print_info "Sandbox environments are now running for testing."
    print_info "Test directory: $SNIPER_SANDBOX_TEST_DIR"
    print_info "Manual test script: $SNIPER_SANDBOX_TEST_DIR/run_tests.sh"
    print_info "To run manual tests: ./sandbox_test/run_tests.sh"
    print_info "When finished, stop environments with: poetry run sniper sandbox stop dvwa juiceshop"
}

# Execute main function
main 