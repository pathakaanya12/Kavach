#!/usr/bin/env bash
set -e

# Kavach - Single command runner for Linux/macOS
echo "=== KAVACH STARTUP ==="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed. Aborting."
    exit 1
fi

# Set up virtual environment if needed
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# Install dependencies if needed
echo "Verifying dependencies..."
pip install -r requirements.txt --quiet

# Offline-safe dashboard: download the Tailwind runtime once (needs internet the first time only)
if [ ! -s "web/tailwind.js" ]; then
    echo "Downloading dashboard styles for offline use (one time)..."
    curl -sSL https://cdn.tailwindcss.com -o web/tailwind.js || wget -qO web/tailwind.js https://cdn.tailwindcss.com || echo "Could not download now; dashboard will use the CDN when online."
fi

# Ensure .env exists
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "Copying .env.example to .env..."
        cp .env.example .env
    fi
fi

# Ensure data directory and files exist
mkdir -p data/files

echo "Starting Kavach Server on http://0.0.0.0:8000..."
exec uvicorn server.main:app --host 0.0.0.0 --port 8000
