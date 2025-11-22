#!/bin/bash
# ARTIS Installation Script for Kali Linux
# Automates the setup of ARTIS and its dependencies

set -e  # Exit on error

echo "========================================="
echo "ARTIS Installation Script for Kali Linux"
echo "========================================="
echo ""

# Check if running on Kali Linux
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is designed for Kali Linux"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Please do not run this script as root"
    echo "   It will prompt for sudo when needed"
    exit 1
fi

echo "📦 Installing system dependencies..."
sudo apt update
sudo apt install -y rabbitmq-server postgresql postgresql-contrib python3-pip python3-venv

echo ""
echo "🐰 Starting RabbitMQ..."
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server

echo ""
echo "🐘 Starting PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

echo ""
echo "💾 Creating ARTIS database..."
sudo -u postgres psql << EOF
-- Drop database if exists (for clean install)
DROP DATABASE IF EXISTS artis;
DROP USER IF EXISTS artis;

-- Create database and user
CREATE DATABASE artis;
CREATE USER artis WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE artis TO artis;
ALTER DATABASE artis OWNER TO artis;
EOF

echo ""
echo "🐍 Setting up Python virtual environment..."
python3 -m venv artis_env
source artis_env/bin/activate

echo ""
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "🔧 Installing ARTIS..."
pip install -e .

echo ""
echo "🗄️  Initializing database..."
python scripts/setup_db.py

echo ""
echo "🚀 Starting Metasploit RPC..."
# Kill existing msfrpcd if running
pkill msfrpcd 2>/dev/null || true
sleep 2
msfrpcd -P msf -S -a 127.0.0.1 &
sleep 3

echo ""
echo "✅ Installation complete!"
echo ""
echo "========================================="
echo "Next Steps:"
echo "========================================="
echo "1. Activate virtual environment:"
echo "   source artis_env/bin/activate"
echo ""
echo "2. Test installation:"
echo "   python test_messagebus.py"
echo ""
echo "3. Start ARTIS:"
echo "   artis"
echo ""
echo "4. Run a test scan:"
echo "   artis scan --target 127.0.0.1 --profile quick"
echo ""
echo "5. Read the quick start guide:"
echo "   cat QUICKSTART.md"
echo ""
echo "⚠️  Remember: Only use ARTIS on authorized systems!"
echo "========================================="
