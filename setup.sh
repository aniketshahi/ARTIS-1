#!/bin/bash
# ARTIS One-Command Setup
# Usage: ./setup.sh

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
    ___    ____  ______  ______
   /   |  / __ \/_  __/ /  _/ /
  / /| | / /_/ / / /    / / / / 
 / ___ |/ _, _/ / /   _/ / /_/  
/_/  |_/_/ |_| /_/   /___/(_)   

Autonomous Red Teaming Integrated System
One-Command Setup for Kali Linux
EOF
echo -e "${NC}"

# Check if running on Kali
if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Warning: This script is optimized for Kali Linux${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}❌ Please do not run this script as root${NC}"
    echo "   It will prompt for sudo when needed"
    exit 1
fi

echo -e "${GREEN}Starting ARTIS installation...${NC}"
echo ""

# Step 1: Install system dependencies
echo -e "${BLUE}[1/7]${NC} Installing system dependencies..."
sudo apt update -qq
sudo apt install -y rabbitmq-server postgresql postgresql-contrib python3-pip python3-venv > /dev/null 2>&1
echo -e "${GREEN}✓${NC} System dependencies installed"

# Step 2: Start and enable services
echo -e "${BLUE}[2/7]${NC} Starting services..."
sudo systemctl start rabbitmq-server > /dev/null 2>&1
sudo systemctl enable rabbitmq-server > /dev/null 2>&1
sudo systemctl start postgresql > /dev/null 2>&1
sudo systemctl enable postgresql > /dev/null 2>&1
echo -e "${GREEN}✓${NC} Services started"

# Step 3: Setup database
echo -e "${BLUE}[3/7]${NC} Setting up PostgreSQL database..."
sudo -u postgres psql > /dev/null 2>&1 << EOF
DROP DATABASE IF EXISTS artis;
DROP USER IF EXISTS artis;
CREATE DATABASE artis;
CREATE USER artis WITH PASSWORD 'artis123';
GRANT ALL PRIVILEGES ON DATABASE artis TO artis;
ALTER DATABASE artis OWNER TO artis;
EOF
echo -e "${GREEN}✓${NC} Database created"

# Step 4: Create virtual environment
echo -e "${BLUE}[4/7]${NC} Creating Python virtual environment..."
python3 -m venv venv > /dev/null 2>&1
source venv/bin/activate
echo -e "${GREEN}✓${NC} Virtual environment created"

# Step 5: Install Python dependencies
echo -e "${BLUE}[5/7]${NC} Installing Python dependencies (this may take a minute)..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt > /dev/null 2>&1
echo -e "${GREEN}✓${NC} Python dependencies installed"

# Step 6: Install ARTIS
echo -e "${BLUE}[6/7]${NC} Installing ARTIS..."
pip install -e . > /dev/null 2>&1
echo -e "${GREEN}✓${NC} ARTIS installed"

# Step 7: Initialize database
echo -e "${BLUE}[7/7]${NC} Initializing database..."

# Create config file from template
if [ ! -f config/artis_config.yaml ]; then
    cp config/artis_config.yaml.template config/artis_config.yaml
fi

python scripts/setup_db.py > /dev/null 2>&1
echo -e "${GREEN}✓${NC} Database initialized"

# Start Metasploit RPC
echo ""
echo -e "${BLUE}Starting Metasploit RPC...${NC}"
pkill msfrpcd 2>/dev/null || true
sleep 1
msfrpcd -P msf -S -a 127.0.0.1 > /dev/null 2>&1 &
sleep 2
echo -e "${GREEN}✓${NC} Metasploit RPC started"

# Create activation script
cat > activate_artis.sh << 'ACTIVATE_EOF'
#!/bin/bash
source venv/bin/activate
export ARTIS_DB_PASSWORD=artis123
echo "ARTIS environment activated!"
echo "Run 'artis' to start the console"
ACTIVATE_EOF
chmod +x activate_artis.sh

# Success message
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}║   ✓ ARTIS Installation Complete!          ║${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo -e "  ${YELLOW}1.${NC} Activate environment:"
echo -e "     ${GREEN}source activate_artis.sh${NC}"
echo ""
echo -e "  ${YELLOW}2.${NC} Start ARTIS:"
echo -e "     ${GREEN}artis${NC}"
echo ""
echo -e "  ${YELLOW}3.${NC} Run a test scan:"
echo -e "     ${GREEN}artis> scan -t 127.0.0.1 -p quick${NC}"
echo ""
echo -e "${BLUE}Service Management:${NC}"
echo -e "  Start services: ${GREEN}./scripts/setup_services.sh start${NC}"
echo -e "  Stop services:  ${GREEN}./scripts/setup_services.sh stop${NC}"
echo -e "  Check status:   ${GREEN}./scripts/setup_services.sh status${NC}"
echo ""
echo -e "${YELLOW}⚠️  Important:${NC} Only use ARTIS on authorized systems!"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo -e "  Quick Start: ${GREEN}cat QUICKSTART.md${NC}"
echo -e "  Full Guide:  ${GREEN}cat README.md${NC}"
echo ""

# Auto-activate for convenience
source venv/bin/activate
export ARTIS_DB_PASSWORD=artis123

echo -e "${GREEN}Environment is now active. Type 'artis' to start!${NC}"
echo ""
