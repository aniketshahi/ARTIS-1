#!/usr/bin/env python3
"""
Test script for ARTIS Message Bus
Verifies RabbitMQ connection and pub/sub functionality
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from artis.core.message_bus import MessageBus, RoutingKeys
from artis.core.logger import setup_logger, get_logger


def test_message_bus():
    """Test message bus functionality"""
    setup_logger(level='INFO')
    logger = get_logger()
    
    logger.info("=" * 60)
    logger.info("ARTIS Message Bus Test")
    logger.info("=" * 60)
    
    try:
        # Initialize message bus
        logger.info("Connecting to RabbitMQ...")
        mb = MessageBus()
        
        # Test publish
        logger.info("Publishing test message...")
        test_message = {
            'type': 'test',
            'message': 'Hello from ARTIS!',
            'timestamp': time.time()
        }
        
        mb.publish(RoutingKeys.VULN_DISCOVERED, test_message)
        logger.info("Message published successfully!")
        
        # Test subscribe
        logger.info("Setting up subscriber...")
        
        def message_handler(message):
            logger.info(f"Received message: {message}")
        
        mb.subscribe(RoutingKeys.ALL_VULNS, message_handler)
        logger.info("Subscriber registered")
        
        # Publish another message
        logger.info("Publishing another test message...")
        mb.publish(RoutingKeys.VULN_NMAP, {'test': 'nmap vulnerability'})
        
        logger.info("=" * 60)
        logger.info("Message bus test completed successfully!")
        logger.info("Press Ctrl+C to stop consuming messages...")
        logger.info("=" * 60)
        
        # Start consuming (blocking)
        mb.start_consuming()
        
    except KeyboardInterrupt:
        logger.info("\nStopping message bus test...")
        mb.close()
    except Exception as e:
        logger.error(f"Message bus test failed: {str(e)}")
        logger.error("Make sure RabbitMQ is running: sudo systemctl start rabbitmq-server")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(test_message_bus())
