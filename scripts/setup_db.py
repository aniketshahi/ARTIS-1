#!/usr/bin/env python3
"""
ARTIS Database Setup Script
Initialize PostgreSQL database and create tables
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from artis.core.config import get_config
from artis.core.database import get_database
from artis.core.logger import get_logger, setup_logger


def main():
    """Setup database"""
    setup_logger(level='INFO')
    logger = get_logger()
    
    logger.info("ARTIS Database Setup")
    logger.info("=" * 60)
    
    try:
        # Load configuration
        config = get_config()
        logger.info(f"Configuration loaded from: {config.config_path}")
        
        # Database connection info
        db_host = config.get('database.host')
        db_port = config.get('database.port')
        db_name = config.get('database.database')
        db_user = config.get('database.username')
        
        logger.info(f"Database: {db_user}@{db_host}:{db_port}/{db_name}")
        
        # Initialize database
        logger.info("Connecting to database...")
        db = get_database()
        
        # Create tables
        logger.info("Creating database tables...")
        db.create_tables()
        
        logger.info("=" * 60)
        logger.info("Database setup completed successfully!")
        logger.info("")
        logger.info("Tables created:")
        logger.info("  - vulnerabilities")
        logger.info("  - exploits")
        logger.info("  - sessions")
        logger.info("  - workflow_state")
        logger.info("")
        logger.info("You can now start ARTIS with: artis")
        
        return 0
    
    except Exception as e:
        logger.error(f"Database setup failed: {str(e)}")
        logger.error("Please ensure PostgreSQL is running and credentials are correct")
        logger.error(f"Check configuration at: {config.config_path if 'config' in locals() else 'config/artis_config.yaml'}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
