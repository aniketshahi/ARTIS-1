"""
ARTIS - Autonomous Red Teaming Integrated System
Main package initialization
"""

__version__ = "0.1.0"
__author__ = "ARTIS Development Team"
__description__ = "Autonomous Red Teaming Integrated System - A Kali Linux command-line tool"

# Package-level imports for convenience
from artis.core.logger import get_logger

__all__ = ['__version__', '__author__', '__description__', 'get_logger']
