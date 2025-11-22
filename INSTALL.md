# ARTIS Installation Guide

## One-Command Installation

ARTIS can be installed and running in under 5 minutes with a single command!

### Prerequisites

- Kali Linux (or Debian-based Linux)
- Internet connection
- Sudo privileges

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/ARTIS.git
cd ARTIS

# 2. Run setup (one command does everything!)
chmod +x setup.sh
./setup.sh

# 3. Activate and run
source activate_artis.sh
artis
```

### What Happens During Setup

The `setup.sh` script automatically performs these steps:

```
[1/7] Installing system dependencies
      ├─ RabbitMQ (message broker)
      ├─ PostgreSQL (database)
      └─ Python 3 + pip

[2/7] Starting services
      ├─ RabbitMQ server
      └─ PostgreSQL server

[3/7] Setting up database
      ├─ Create 'artis' database
      ├─ Create 'artis' user
      └─ Grant permissions

[4/7] Creating Python virtual environment
      └─ venv/ directory

[5/7] Installing Python dependencies
      └─ 38 packages from requirements.txt

[6/7] Installing ARTIS
      └─ Editable install (pip install -e .)

[7/7] Initializing database
      ├─ Create tables (vulnerabilities, exploits, sessions, workflow_state)
      └─ Start Metasploit RPC
```

### Post-Installation

After installation completes, you'll see:

```
╔════════════════════════════════════════════╗
║                                            ║
║   ✓ ARTIS Installation Complete!          ║
║                                            ║
╚════════════════════════════════════════════╝

Quick Start:

  1. Activate environment:
     source activate_artis.sh

  2. Start ARTIS:
     artis

  3. Run a test scan:
     artis> scan -t 127.0.0.1 -p quick
```

### First Run

```bash
# Activate the environment
source activate_artis.sh

# Start ARTIS console
artis

# You'll see:
    ___    ____  ______  ______
   /   |  / __ \/_  __/ /  _/ /
  / /| | / /_/ / / /    / / / / 
 / ___ |/ _, _/ / /   _/ / /_/  
/_/  |_/_/ |_| /_/   /___/(_)   

Autonomous Red Teaming Integrated System
Version 0.1.0 - Phase 1 MVP
⚠  Use only on authorized systems  ⚠

Type 'help' for available commands
Type 'exit' to quit

artis>
```

### Test the Installation

```bash
# In the ARTIS console
artis> status                    # Check system status
artis> db init                   # Initialize database (if needed)
artis> scan -t 127.0.0.1 -p quick  # Scan localhost
artis> vulns list                # List findings
```

## Manual Installation

If you prefer to install manually or need to troubleshoot:

### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y rabbitmq-server postgresql postgresql-contrib python3-pip python3-venv
```

### 2. Start Services

```bash
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 3. Create Database

```bash
sudo -u postgres psql << EOF
CREATE DATABASE artis;
CREATE USER artis WITH PASSWORD 'artis123';
GRANT ALL PRIVILEGES ON DATABASE artis TO artis;
ALTER DATABASE artis OWNER TO artis;
\q
EOF
```

### 4. Setup Python Environment

```bash
cd ARTIS
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### 5. Initialize Database

```bash
python scripts/setup_db.py
```

### 6. Start Metasploit RPC

```bash
msfrpcd -P msf -S -a 127.0.0.1 &
```

### 7. Run ARTIS

```bash
artis
```

## Service Management

### Start All Services

```bash
./scripts/setup_services.sh start
```

### Stop All Services

```bash
./scripts/setup_services.sh stop
```

### Check Service Status

```bash
./scripts/setup_services.sh status
```

### Restart Services

```bash
./scripts/setup_services.sh restart
```

## Configuration

### Database Password

Default password is `artis123`. To change:

1. Edit `config/artis_config.yaml`:
   ```yaml
   database:
     password: your_new_password
   ```

2. Or use environment variable:
   ```bash
   export ARTIS_DB_PASSWORD=your_new_password
   ```

### Metasploit RPC

Default password is `msf`. To change:

1. Start msfrpcd with custom password:
   ```bash
   msfrpcd -P your_password -S -a 127.0.0.1
   ```

2. Update `config/artis_config.yaml`:
   ```yaml
   tools:
     metasploit:
       rpc_password: your_password
   ```

## Troubleshooting

### Setup Script Fails

```bash
# Check the error message
# Common issues:

# 1. RabbitMQ won't start
sudo systemctl status rabbitmq-server
sudo journalctl -u rabbitmq-server -n 50

# 2. PostgreSQL won't start
sudo systemctl status postgresql
sudo journalctl -u postgresql -n 50

# 3. Permission denied
# Make sure you're not running as root
whoami  # Should NOT be 'root'
```

### Database Connection Issues

```bash
# Test database connection
psql -h localhost -U artis -d artis

# If it fails, check PostgreSQL is running
sudo systemctl status postgresql

# Reset database
artis db clear  # WARNING: Deletes all data
artis db init
```

### Python Dependencies Fail

```bash
# Update pip
pip install --upgrade pip

# Install dependencies one by one to find the issue
pip install -r requirements.txt -v
```

### Metasploit RPC Not Connecting

```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Kill and restart
pkill msfrpcd
msfrpcd -P msf -S -a 127.0.0.1

# Test connection
msfconsole
msf6> load msgrpc Pass=msf
```

## Uninstallation

To completely remove ARTIS:

```bash
# 1. Stop services
./scripts/setup_services.sh stop

# 2. Remove database
sudo -u postgres psql -c "DROP DATABASE artis;"
sudo -u postgres psql -c "DROP USER artis;"

# 3. Remove virtual environment
rm -rf venv/

# 4. Remove ARTIS directory
cd ..
rm -rf ARTIS/
```

## Next Steps

After installation:

1. **Read the documentation**
   - `cat QUICKSTART.md`
   - `cat README.md`

2. **Configure targets**
   - Edit `config/targets.yaml`

3. **Test with safe targets**
   - Use Metasploitable VM
   - Scan localhost first

4. **Review logs**
   - Check `logs/artis.log`

5. **Join the community**
   - Report issues on GitHub
   - Contribute improvements

---

**Installation complete! Happy (ethical) hacking! 🎯**
