# ARTIS Quick Start Guide

## Prerequisites

ARTIS is designed for **Kali Linux** and requires:
- Python 3.8+
- RabbitMQ
- PostgreSQL
- Metasploit Framework
- Nmap (pre-installed on Kali)
- searchsploit (pre-installed on Kali)

## Installation

### 1. Install System Dependencies

```bash
# Update system
sudo apt update

# Install RabbitMQ
sudo apt install -y rabbitmq-server
sudo systemctl start rabbitmq-server
sudo systemctl enable rabbitmq-server

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2. Setup Database

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE artis;
CREATE USER artis WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE artis TO artis;
ALTER DATABASE artis OWNER TO artis;
\q
EOF
```

### 3. Install ARTIS

```bash
# Clone or navigate to ARTIS directory
cd /path/to/ARTIS

# Create virtual environment (recommended)
python3 -m venv artis_env
source artis_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install ARTIS
pip install -e .

# Initialize database
python scripts/setup_db.py
```

### 4. Start Metasploit RPC (for exploitation)

```bash
# Start msfrpcd in background
msfrpcd -P msf -S -a 127.0.0.1 &

# Verify it's running
ps aux | grep msfrpcd
```

## Quick Start

### Test Installation

```bash
# Test message bus
python test_messagebus.py

# Start ARTIS console
artis

# Check system status
artis> status

# Initialize database (if needed)
artis> db init
```

### Run Your First Scan

```bash
# Scan localhost (safe test)
artis scan --target 127.0.0.1 --profile quick

# Or in interactive mode
artis
artis> scan -t 127.0.0.1 -p quick
artis> vulns list
```

### Run Automated Workflow

```bash
# Edit targets configuration
nano config/targets.yaml

# Run workflow
artis workflow start --config config/targets.yaml

# Or in interactive mode
artis
artis> workflow start
Enter target (IP/CIDR): 192.168.1.100
```

## Common Commands

### Interactive Console

```bash
artis                                    # Start interactive console
artis> help                              # Show all commands
artis> scan -t 192.168.1.0/24 -p thorough  # Scan network
artis> vulns list --severity critical    # List critical vulnerabilities
artis> vulns show <id>                   # Show vulnerability details
artis> workflow start                    # Start automated workflow
artis> workflow status                   # Check workflow status
artis> sessions list                     # List active sessions
artis> db status                         # Database status
artis> exit                              # Exit console
```

### Non-Interactive CLI

```bash
artis scan --target 192.168.1.0/24 --profile thorough
artis vulns list --format json --severity critical
artis workflow start --config config/targets.yaml --output report.html
artis workflow status
artis sessions list --status active
artis db init
```

## Configuration

### Main Configuration

Edit `config/artis_config.yaml`:

```yaml
message_bus:
  host: localhost
  port: 5672
  username: guest
  password: guest

database:
  host: localhost
  port: 5432
  database: artis
  username: artis
  password: changeme

tools:
  metasploit:
    rpc_host: localhost
    rpc_port: 55553
```

### Environment Variables

You can override configuration with environment variables:

```bash
export ARTIS_DB_HOST=localhost
export ARTIS_DB_PASSWORD=your_password
export ARTIS_MSF_RPC_HOST=localhost
```

## Troubleshooting

### RabbitMQ Connection Failed

```bash
# Check if RabbitMQ is running
sudo systemctl status rabbitmq-server

# Restart if needed
sudo systemctl restart rabbitmq-server

# Check logs
sudo journalctl -u rabbitmq-server -f
```

### Database Connection Failed

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -U artis -d artis

# Reset database
artis db clear  # WARNING: Deletes all data!
artis db init
```

### Metasploit RPC Not Connected

```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Start msfrpcd
msfrpcd -P msf -S -a 127.0.0.1

# Test connection
msfconsole
msf6> load msgrpc Pass=msf
```

### Nmap Permission Denied

```bash
# Run with sudo or add capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

## Testing with Metasploitable

For safe testing, use Metasploitable VM:

```bash
# Download Metasploitable 2
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip

# Import to VirtualBox/VMware
# Note the IP address (e.g., 192.168.1.200)

# Scan with ARTIS
artis scan --target 192.168.1.200 --profile thorough

# Run full workflow
artis workflow start
Enter target: 192.168.1.200
```

## Security Warnings

⚠️ **IMPORTANT**: 
- Only use ARTIS on systems you own or have explicit written authorization to test
- Unauthorized access to computer systems is illegal
- Always maintain proper documentation of authorization
- Use in isolated lab environments for testing

## Next Steps

1. Review the full documentation in `README.md`
2. Check the walkthrough in `walkthrough.md`
3. Customize `config/targets.yaml` for your environment
4. Run tests in a safe lab environment
5. Review logs in `logs/artis.log`

## Support

- Documentation: `README.md`, `walkthrough.md`
- Configuration: `config/artis_config.yaml`
- Logs: `logs/artis.log`
- Database: PostgreSQL on localhost:5432

Happy (ethical) hacking! 🎯
