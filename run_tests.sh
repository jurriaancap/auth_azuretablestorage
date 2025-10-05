#!/bin/bash

# Test runner script for authentication app

set -e  # Exit on any error

echo "== Running Authentication App Tests"
echo "=================================== "

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "main.py" ] || [ ! -d "tests" ]; then
    print_error "Must be run from the authentication app root directory"
    exit 1
fi

# Activate virtual environment if available
if [ -d ".venv" ]; then
    print_status "Activating virtual environment..."
    source .venv/bin/activate
fi

# Install test dependencies if needed
if ! python -c "import pytest" 2>/dev/null; then
    print_warning "Installing test dependencies..."
    uv add --group dev pytest pytest-cov pytest-mock httpx
fi

# Parse command line arguments
case "${1:-all}" in
    "unit")
        print_status "Running unit tests..."
        python -m pytest tests/test_auth_helpers.py tests/test_auth_mfa.py -v
        ;;
    "integration") 
        print_status "Running integration tests..."
        python -m pytest tests/test_integration.py -v
        ;;
    "endpoints")
        print_status "Running endpoint tests..."
        python -m pytest tests/test_main.py -v
        ;;
    "coverage")
        print_status "Running tests with coverage..."
        python -m pytest --cov=auth --cov=main --cov-report=term-missing --cov-report=html
        print_status "Coverage report generated in htmlcov/"
        ;;
    "fast")
        print_status "Running fast tests only..."
        python -m pytest -v -m "not slow"
        ;;
    "all"|"")
        print_status "Running all tests..."
        python -m pytest -v
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [OPTION]"
        echo ""
        echo "Options:"
        echo "  all          Run all tests (default)"
        echo "  unit         Run only unit tests" 
        echo "  integration  Run only integration tests"
        echo "  endpoints    Run only endpoint tests"
        echo "  coverage     Run tests with coverage report"
        echo "  fast         Run fast tests only (exclude slow tests)"
        echo "  help         Show this help message"
        exit 0
        ;;
    *)
        print_error "Unknown option: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac

echo ""
print_status "Tests completed successfully!"