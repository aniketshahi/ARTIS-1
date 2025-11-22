"""
ARTIS Logging System
Centralized logging with JSON formatting and audit trail
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger


class ARTISLogger:
    """
    Custom logger for ARTIS with JSON formatting and audit capabilities
    """
    
    def __init__(self, name: str = "artis", log_file: Optional[str] = None, level: str = "INFO"):
        """
        Initialize logger
        
        Args:
            name: Logger name
            log_file: Path to log file
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # JSON formatter
        json_formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s %(module)s %(funcName)s',
            rename_fields={'levelname': 'level', 'asctime': 'timestamp'}
        )
        
        # Console handler (human-readable for CLI)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler (JSON for parsing)
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(json_formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(message, extra=kwargs)
    
    def audit(self, action: str, target: str, result: str, **kwargs):
        """
        Log audit trail for offensive actions
        
        Args:
            action: Action performed (e.g., 'scan', 'exploit', 'session_created')
            target: Target of action (IP, hostname, etc.)
            result: Result of action (success, failure, error)
            **kwargs: Additional context
        """
        audit_data = {
            'audit': True,
            'action': action,
            'target': target,
            'result': result,
            **kwargs
        }
        self.logger.info(f"AUDIT: {action} on {target} - {result}", extra=audit_data)


# Global logger instance
_logger: Optional[ARTISLogger] = None


def get_logger(name: str = "artis", log_file: Optional[str] = None, level: str = "INFO") -> ARTISLogger:
    """
    Get global logger instance
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        
    Returns:
        ARTISLogger instance
    """
    global _logger
    if _logger is None:
        # Try to get log file from config
        if log_file is None:
            try:
                from artis.core.config import get_config
                config = get_config()
                log_file = config.get('logging.file', 'logs/artis.log')
                level = config.get('logging.level', 'INFO')
            except:
                log_file = 'logs/artis.log'
        
        _logger = ARTISLogger(name, log_file, level)
    
    return _logger


def setup_logger(name: str = "artis", log_file: Optional[str] = None, level: str = "INFO"):
    """
    Setup and configure logger
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
    """
    global _logger
    _logger = ARTISLogger(name, log_file, level)
