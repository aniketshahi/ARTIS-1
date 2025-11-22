"""
ARTIS Message Bus
RabbitMQ abstraction layer for inter-module communication
"""

import json
import pika
import threading
from typing import Callable, Dict, Any, Optional
from artis.core.logger import get_logger
from artis.core.config import get_config


class MessageBus:
    """
    Message bus abstraction for RabbitMQ
    Provides publish/subscribe functionality for module communication
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize message bus
        
        Args:
            config: Message bus configuration (uses global config if None)
        """
        self.logger = get_logger()
        
        if config is None:
            cfg = get_config()
            config = {
                'host': cfg.get('message_bus.host', 'localhost'),
                'port': cfg.get('message_bus.port', 5672),
                'username': cfg.get('message_bus.username', 'guest'),
                'password': cfg.get('message_bus.password', 'guest'),
                'vhost': cfg.get('message_bus.vhost', '/'),
                'exchange': cfg.get('message_bus.exchange', 'artis'),
            }
        
        self.config = config
        self.connection: Optional[pika.BlockingConnection] = None
        self.channel: Optional[pika.channel.Channel] = None
        self.exchange = config['exchange']
        self.subscribers: Dict[str, Callable] = {}
        self._connect()
    
    def _connect(self):
        """Establish connection to RabbitMQ"""
        try:
            credentials = pika.PlainCredentials(
                self.config['username'],
                self.config['password']
            )
            
            parameters = pika.ConnectionParameters(
                host=self.config['host'],
                port=self.config['port'],
                virtual_host=self.config['vhost'],
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )
            
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            # Declare exchange (topic-based routing)
            self.channel.exchange_declare(
                exchange=self.exchange,
                exchange_type='topic',
                durable=True
            )
            
            self.logger.info(
                f"Connected to RabbitMQ at {self.config['host']}:{self.config['port']}",
                exchange=self.exchange
            )
            
        except Exception as e:
            self.logger.error(f"Failed to connect to RabbitMQ: {str(e)}")
            raise
    
    def _ensure_connection(self):
        """Ensure connection is alive, reconnect if necessary"""
        if self.connection is None or self.connection.is_closed:
            self.logger.warning("Connection lost, reconnecting...")
            self._connect()
    
    def publish(self, routing_key: str, message: Dict[str, Any]):
        """
        Publish message to exchange
        
        Args:
            routing_key: Routing key (e.g., 'artis.vuln.discovered')
            message: Message payload (will be JSON serialized)
        """
        self._ensure_connection()
        
        try:
            body = json.dumps(message)
            
            self.channel.basic_publish(
                exchange=self.exchange,
                routing_key=routing_key,
                body=body,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent message
                    content_type='application/json'
                )
            )
            
            self.logger.debug(
                f"Published message to {routing_key}",
                routing_key=routing_key,
                message_size=len(body)
            )
            
        except Exception as e:
            self.logger.error(
                f"Failed to publish message: {str(e)}",
                routing_key=routing_key
            )
            raise
    
    def subscribe(self, routing_key: str, callback: Callable[[Dict[str, Any]], None], queue_name: Optional[str] = None):
        """
        Subscribe to messages matching routing key
        
        Args:
            routing_key: Routing key pattern (supports wildcards: * and #)
            callback: Callback function to handle messages
            queue_name: Optional queue name (auto-generated if None)
        """
        self._ensure_connection()
        
        try:
            # Declare queue
            if queue_name is None:
                queue_name = f"artis.{routing_key.replace('*', 'any').replace('#', 'all')}"
            
            result = self.channel.queue_declare(queue=queue_name, durable=True)
            queue_name = result.method.queue
            
            # Bind queue to exchange with routing key
            self.channel.queue_bind(
                exchange=self.exchange,
                queue=queue_name,
                routing_key=routing_key
            )
            
            # Create wrapper callback for message handling
            def message_handler(ch, method, properties, body):
                try:
                    message = json.loads(body)
                    self.logger.debug(
                        f"Received message from {method.routing_key}",
                        routing_key=method.routing_key
                    )
                    callback(message)
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except Exception as e:
                    self.logger.error(
                        f"Error processing message: {str(e)}",
                        routing_key=method.routing_key
                    )
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            
            # Set up consumer
            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(
                queue=queue_name,
                on_message_callback=message_handler
            )
            
            self.subscribers[routing_key] = callback
            
            self.logger.info(
                f"Subscribed to {routing_key}",
                routing_key=routing_key,
                queue=queue_name
            )
            
        except Exception as e:
            self.logger.error(
                f"Failed to subscribe: {str(e)}",
                routing_key=routing_key
            )
            raise
    
    def start_consuming(self):
        """Start consuming messages (blocking)"""
        self._ensure_connection()
        
        try:
            self.logger.info("Starting message consumption...")
            self.channel.start_consuming()
        except KeyboardInterrupt:
            self.logger.info("Stopping message consumption...")
            self.stop_consuming()
        except Exception as e:
            self.logger.error(f"Error during consumption: {str(e)}")
            raise
    
    def stop_consuming(self):
        """Stop consuming messages"""
        if self.channel and not self.channel.is_closed:
            self.channel.stop_consuming()
    
    def close(self):
        """Close connection to RabbitMQ"""
        try:
            if self.channel and not self.channel.is_closed:
                self.channel.close()
            if self.connection and not self.connection.is_closed:
                self.connection.close()
            self.logger.info("Closed RabbitMQ connection")
        except Exception as e:
            self.logger.error(f"Error closing connection: {str(e)}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Global message bus instance
_message_bus: Optional[MessageBus] = None


def get_message_bus(config: Optional[Dict[str, Any]] = None) -> MessageBus:
    """
    Get global message bus instance
    
    Args:
        config: Message bus configuration
        
    Returns:
        MessageBus instance
    """
    global _message_bus
    if _message_bus is None:
        _message_bus = MessageBus(config)
    return _message_bus


# Routing key constants for common message types
class RoutingKeys:
    """Standard routing keys for ARTIS messages"""
    
    # Vulnerability discovery
    VULN_DISCOVERED = "artis.vuln.discovered"
    VULN_NMAP = "artis.vuln.nmap.discovered"
    VULN_NESSUS = "artis.vuln.nessus.discovered"
    VULN_ZAP = "artis.vuln.zap.discovered"
    
    # Exploit selection
    EXPLOIT_FOUND = "artis.exploit.found"
    EXPLOIT_READY = "artis.exploit.ready"
    EXPLOIT_FAILED = "artis.exploit.failed"
    
    # Session management
    SESSION_CREATED = "artis.session.created"
    SESSION_LOST = "artis.session.lost"
    SESSION_COMMAND = "artis.session.command"
    
    # Workflow
    WORKFLOW_START = "artis.workflow.start"
    WORKFLOW_COMPLETE = "artis.workflow.complete"
    WORKFLOW_ERROR = "artis.workflow.error"
    
    # Wildcard patterns
    ALL_VULNS = "artis.vuln.#"
    ALL_EXPLOITS = "artis.exploit.#"
    ALL_SESSIONS = "artis.session.#"
    ALL_MESSAGES = "artis.#"
