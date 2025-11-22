#!/bin/bash

# Security Tester v2.0 - Setup Script
# This script helps set up the development environment

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Security Tester v2.0 - Setup Script             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
echo "✓ Checking Python version..."
python3 --version

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "✓ Creating virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "✓ Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "✓ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "✓ Installing dependencies..."
pip install -r requirements.txt

# Check if Redis is installed
echo "✓ Checking Redis..."
if command -v redis-cli &> /dev/null; then
    echo "  Redis is installed"
    if redis-cli ping &> /dev/null; then
        echo "  Redis is running ✓"
    else
        echo "  Redis is not running. Starting Redis..."
        echo "  Please start Redis manually: sudo systemctl start redis"
    fi
else
    echo "  ⚠ Redis is not installed!"
    echo "  Install Redis:"
    echo "    Ubuntu/Debian: sudo apt-get install redis-server"
    echo "    macOS: brew install redis"
    echo "    Docker: docker run -d -p 6379:6379 redis:latest"
fi

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "✓ Creating .env file..."
    echo "FLASK_ENV=development" > .env
    echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
    echo "PORT=4444" >> .env
    echo "DATABASE_URL=sqlite:///security_tester.db" >> .env
    echo "REDIS_URL=redis://localhost:6379/0" >> .env
    echo "CELERY_BROKER_URL=redis://localhost:6379/1" >> .env
    echo "CELERY_RESULT_BACKEND=redis://localhost:6379/2" >> .env
    echo "ADMIN_EMAIL=admin@example.com" >> .env
    echo "ADMIN_PASSWORD=admin123" >> .env
    echo "  ⚠ .env created with default values. Please update ADMIN_EMAIL and ADMIN_PASSWORD!"
else
    echo "✓ .env file already exists"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                   Setup Complete!                          ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  To start the application:                                 ║"
echo "║                                                            ║"
echo "║  1. Terminal 1 - Start Flask:                             ║"
echo "║     source venv/bin/activate                              ║"
echo "║     PORT=4444 python app.py                               ║"
echo "║                                                            ║"
echo "║  2. Terminal 2 - Start Celery:                            ║"
echo "║     source venv/bin/activate                              ║"
echo "║     celery -A celery_worker.celery worker --loglevel=info ║"
echo "║                                                            ║"
echo "║  3. Open browser: http://localhost:4444                   ║"
echo "║                                                            ║"
echo "║  Default admin: admin@example.com / admin123              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

