# ARTIS - Autonomous Red Teaming Integrated System

![ARTIS Banner](https://img.shields.io/badge/ARTIS-v0.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-red)

**Automated Penetration Testing Framework for Kali Linux**

## 🚀 Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/ARTIS.git
cd ARTIS

# Run one-command setup
chmod +x setup.sh
./setup.sh

# Activate environment and start
source activate_artis.sh
artis
```

That's it! ARTIS is now ready to use.

## ⚡ Quick Start

### Run Your First Scan
```bash
# Start ARTIS console
artis

# Scan a target
artis> scan -t 127.0.0.1 -p quick

# List vulnerabilities
artis> vulns list

# Run automated workflow
artis> workflow start
```

### Non-Interactive Mode
```bash
# Scan from command line
artis scan --target 192.168.1.0/24 --profile thorough

# Run workflow
artis workflow start --config config/targets.yaml
```

## 📋 What Gets Installed

The `setup.sh` script automatically:
- ✅ Installs RabbitMQ and PostgreSQL
- ✅ Creates database and user
- ✅ Sets up Python virtual environment
- ✅ Installs all dependencies
- ✅ Initializes database schema
- ✅ Starts Metasploit RPC
- ✅ Creates activation script

## 🎯 Features

### Core Capabilities
- **Automated Scanning**: Nmap integration with intelligent vulnerability detection
- **Exploit Mapping**: Searches Metasploit and Exploit-DB for matching exploits
- **Automated Exploitation**: Executes exploits and manages C2 sessions
- **Workflow Orchestration**: End-to-end "scan-to-shell" automation
- **Interactive Console**: msfconsole-style interface with tab completion

### Architecture
- **Message-Driven**: RabbitMQ for asynchronous module communication
- **Database**: PostgreSQL with STIX 2.x format
- **Modular**: Easy to extend with new tools and capabilities
- **Audit Logging**: Comprehensive logging of all actions

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Detailed installation and usage guide
- **[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)** - Architecture overview
- **[README.md](README.md)** - Full documentation

## 🛠️ Service Management

```bash
# Start all services
./scripts/setup_services.sh start

# Stop all services
./scripts/setup_services.sh stop

# Check status
./scripts/setup_services.sh status
```

## 🔧 Configuration

Edit `config/artis_config.yaml` to customize:
- Database credentials
- Metasploit RPC settings
- Scan profiles
- Workflow parameters

Edit `config/targets.yaml` to define authorized targets.

## ⚠️ Legal Disclaimer

**IMPORTANT**: ARTIS is designed ONLY for authorized penetration testing and security research.

- ✅ Use only on systems you own or have explicit written authorization to test
- ❌ Unauthorized access to computer systems is illegal
- 📝 Always maintain proper documentation of authorization
- 🔬 Use in isolated lab environments for testing

**You are solely responsible for compliance with all applicable laws.**

## 🧪 Testing

Test with Metasploitable VM (intentionally vulnerable):
```bash
# Download Metasploitable 2
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip

# After setting up the VM, scan it
artis scan --target <metasploitable-ip> --profile thorough
```

## 🐛 Troubleshooting

### Services won't start
```bash
sudo systemctl status rabbitmq-server
sudo systemctl status postgresql
```

### Database connection failed
```bash
# Reset database
artis db clear
artis db init
```

### Metasploit RPC not connecting
```bash
# Restart msfrpcd
pkill msfrpcd
msfrpcd -P msf -S -a 127.0.0.1
```

## 📊 System Requirements

- **OS**: Kali Linux (recommended) or Debian-based Linux
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 10GB free space
- **Network**: Internet connection for initial setup

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🔗 Links

- **Documentation**: [Full Docs](README.md)
- **Issues**: [Report Bugs](https://github.com/yourusername/ARTIS/issues)
- **Wiki**: [Project Wiki](https://github.com/yourusername/ARTIS/wiki)

## 🎓 Credits

ARTIS integrates and automates the following excellent tools:
- **Nmap** - Network scanning
- **Metasploit Framework** - Exploitation
- **Exploit-DB** - Exploit database
- **RabbitMQ** - Message broker
- **PostgreSQL** - Database

---

**Made with ❤️ for the security community**

*Remember: With great power comes great responsibility. Use ethically!*
