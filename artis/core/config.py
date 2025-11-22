"""
ARTIS Configuration Management
Handles loading and validation of configuration from YAML files
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """
    Configuration manager for ARTIS
    Loads configuration from YAML files and environment variables
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration
        
        Args:
            config_path: Path to configuration file. If None, uses default locations.
        """
        self.config_data: Dict[str, Any] = {}
        self.config_path = self._find_config_path(config_path)
        self._load_config()
        self._apply_env_overrides()
        self._validate_config()
    
    def _find_config_path(self, config_path: Optional[str]) -> Path:
        """
        Find configuration file in standard locations
        
        Args:
            config_path: User-provided config path
            
        Returns:
            Path to configuration file
        """
        if config_path:
            return Path(config_path)
        
        # Search in standard locations
        search_paths = [
            Path.cwd() / "config" / "artis_config.yaml",
            Path.home() / ".artis" / "config.yaml",
            Path("/etc/artis/config.yaml"),
        ]
        
        for path in search_paths:
            if path.exists():
                return path
        
        # Return default path (will be created if doesn't exist)
        return Path.cwd() / "config" / "artis_config.yaml"
    
    def _load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            # Create default configuration
            self._create_default_config()
        
        with open(self.config_path, 'r') as f:
            self.config_data = yaml.safe_load(f) or {}
    
    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            'message_bus': {
                'type': 'rabbitmq',
                'host': 'localhost',
                'port': 5672,
                'username': 'guest',
                'password': 'guest',
                'vhost': '/',
                'exchange': 'artis',
            },
            'database': {
                'type': 'postgresql',
                'host': 'localhost',
                'port': 5432,
                'database': 'artis',
                'username': 'artis',
                'password': 'changeme',
            },
            'tools': {
                'nmap': {
                    'path': '/usr/bin/nmap',
                    'default_profile': 'thorough',
                },
                'metasploit': {
                    'rpc_host': 'localhost',
                    'rpc_port': 55553,
                    'rpc_ssl': False,
                    'framework_path': '/usr/share/metasploit-framework',
                },
                'exploitdb': {
                    'path': '/usr/share/exploitdb',
                    'searchsploit': '/usr/bin/searchsploit',
                },
                'zap': {
                    'api_key': '',
                    'host': 'localhost',
                    'port': 8080,
                },
                'nessus': {
                    'enabled': False,
                    'url': 'https://localhost:8834',
                    'access_key': '',
                    'secret_key': '',
                },
            },
            'orchestration': {
                'max_concurrent_scans': 5,
                'scan_timeout': 3600,
                'exploit_timeout': 300,
                'max_retries': 3,
                'retry_delay': 10,
            },
            'logging': {
                'level': 'INFO',
                'format': 'json',
                'file': 'logs/artis.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5,
            },
        }
        
        # Create config directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        self.config_data = default_config
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        # Message bus
        if os.getenv('ARTIS_RABBITMQ_HOST'):
            self.config_data['message_bus']['host'] = os.getenv('ARTIS_RABBITMQ_HOST')
        if os.getenv('ARTIS_RABBITMQ_PORT'):
            self.config_data['message_bus']['port'] = int(os.getenv('ARTIS_RABBITMQ_PORT'))
        
        # Database
        if os.getenv('ARTIS_DB_HOST'):
            self.config_data['database']['host'] = os.getenv('ARTIS_DB_HOST')
        if os.getenv('ARTIS_DB_PORT'):
            self.config_data['database']['port'] = int(os.getenv('ARTIS_DB_PORT'))
        if os.getenv('ARTIS_DB_NAME'):
            self.config_data['database']['database'] = os.getenv('ARTIS_DB_NAME')
        if os.getenv('ARTIS_DB_USER'):
            self.config_data['database']['username'] = os.getenv('ARTIS_DB_USER')
        if os.getenv('ARTIS_DB_PASSWORD'):
            self.config_data['database']['password'] = os.getenv('ARTIS_DB_PASSWORD')
        
        # Metasploit
        if os.getenv('ARTIS_MSF_RPC_HOST'):
            self.config_data['tools']['metasploit']['rpc_host'] = os.getenv('ARTIS_MSF_RPC_HOST')
        if os.getenv('ARTIS_MSF_RPC_PORT'):
            self.config_data['tools']['metasploit']['rpc_port'] = int(os.getenv('ARTIS_MSF_RPC_PORT'))
    
    def _validate_config(self):
        """Validate configuration"""
        required_sections = ['message_bus', 'database', 'tools', 'orchestration', 'logging']
        
        for section in required_sections:
            if section not in self.config_data:
                raise ValueError(f"Missing required configuration section: {section}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'message_bus.host')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'message_bus.host')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self):
        """Save configuration to file"""
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config_data, f, default_flow_style=False)
    
    def __getitem__(self, key: str) -> Any:
        """Allow dict-like access"""
        return self.get(key)
    
    def __setitem__(self, key: str, value: Any):
        """Allow dict-like assignment"""
        self.set(key, value)


# Global configuration instance
_config: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Get global configuration instance
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Config instance
    """
    global _config
    if _config is None:
        _config = Config(config_path)
    return _config


def reload_config(config_path: Optional[str] = None):
    """
    Reload configuration from file
    
    Args:
        config_path: Path to configuration file
    """
    global _config
    _config = Config(config_path)
