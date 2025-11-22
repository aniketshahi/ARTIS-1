"""
ARTIS Database Layer
PostgreSQL database with SQLAlchemy ORM
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, JSON, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session as DBSession
from sqlalchemy.dialects.postgresql import UUID, INET
import uuid

from artis.core.logger import get_logger
from artis.core.config import get_config

# Base class for all models
Base = declarative_base()


class Vulnerability(Base):
    """Vulnerability data model"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_ip = Column(INET, nullable=False, index=True)
    target_port = Column(Integer)
    service_name = Column(String(255))
    service_version = Column(String(255))
    cve_id = Column(String(50), index=True)
    cvss_score = Column(Float)
    severity = Column(String(20))  # low, medium, high, critical
    description = Column(Text)
    source_tool = Column(String(50))  # nmap, nessus, zap
    discovered_at = Column(DateTime, default=datetime.utcnow)
    stix_data = Column(JSON)  # STIX 2.x representation
    
    # Relationships
    exploits = relationship("Exploit", back_populates="vulnerability")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': str(self.id),
            'target_ip': str(self.target_ip),
            'target_port': self.target_port,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'severity': self.severity,
            'description': self.description,
            'source_tool': self.source_tool,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'stix_data': self.stix_data,
        }


class Exploit(Base):
    """Exploit data model"""
    __tablename__ = 'exploits'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey('vulnerabilities.id'))
    exploit_name = Column(String(255), nullable=False)
    exploit_path = Column(String(500))  # Metasploit module path or Exploit-DB path
    exploit_type = Column(String(50))  # metasploit, exploitdb, custom
    payload_type = Column(String(100))
    payload_config = Column(JSON)  # Payload options (LHOST, LPORT, etc.)
    rank = Column(Integer)  # Exploit reliability rank
    success_rate = Column(Float, default=0.0)  # Historical success rate
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="exploits")
    sessions = relationship("Session", back_populates="exploit")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': str(self.id),
            'vulnerability_id': str(self.vulnerability_id),
            'exploit_name': self.exploit_name,
            'exploit_path': self.exploit_path,
            'exploit_type': self.exploit_type,
            'payload_type': self.payload_type,
            'payload_config': self.payload_config,
            'rank': self.rank,
            'success_rate': self.success_rate,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class Session(Base):
    """C2 Session data model"""
    __tablename__ = 'sessions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    exploit_id = Column(UUID(as_uuid=True), ForeignKey('exploits.id'))
    target_ip = Column(INET, nullable=False)
    target_hostname = Column(String(255))
    c2_framework = Column(String(50))  # meterpreter, empire, etc.
    session_id = Column(String(100))  # Framework-specific session ID
    session_status = Column(String(20))  # active, dead, background
    session_type = Column(String(50))  # shell, meterpreter, etc.
    username = Column(String(100))  # User context
    privileges = Column(String(50))  # user, admin, system
    established_at = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)
    session_metadata = Column(JSON)  # Additional session metadata (renamed from 'metadata' to avoid SQLAlchemy conflict)
    
    # Relationships
    exploit = relationship("Exploit", back_populates="sessions")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': str(self.id),
            'exploit_id': str(self.exploit_id) if self.exploit_id else None,
            'target_ip': str(self.target_ip),
            'target_hostname': self.target_hostname,
            'c2_framework': self.c2_framework,
            'session_id': self.session_id,
            'session_status': self.session_status,
            'session_type': self.session_type,
            'username': self.username,
            'privileges': self.privileges,
            'established_at': self.established_at.isoformat() if self.established_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'session_metadata': self.session_metadata,
        }


class WorkflowState(Base):
    """Workflow state tracking"""
    __tablename__ = 'workflow_state'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_name = Column(String(100), nullable=False)
    target = Column(String(255))
    current_step = Column(String(100))
    status = Column(String(20))  # running, completed, failed
    state_data = Column(JSON)  # Workflow-specific state
    started_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': str(self.id),
            'workflow_name': self.workflow_name,
            'target': self.target,
            'current_step': self.current_step,
            'status': self.status,
            'state_data': self.state_data,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }


class Database:
    """Database manager"""
    
    def __init__(self, connection_string: Optional[str] = None):
        """
        Initialize database connection
        
        Args:
            connection_string: PostgreSQL connection string
        """
        self.logger = get_logger()
        
        if connection_string is None:
            config = get_config()
            db_config = {
                'host': config.get('database.host', 'localhost'),
                'port': config.get('database.port', 5432),
                'database': config.get('database.database', 'artis'),
                'username': config.get('database.username', 'artis'),
                'password': config.get('database.password', 'changeme'),
            }
            connection_string = (
                f"postgresql://{db_config['username']}:{db_config['password']}"
                f"@{db_config['host']}:{db_config['port']}/{db_config['database']}"
            )
        
        self.engine = create_engine(connection_string, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        self.logger.info("Database connection initialized")
    
    def create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(self.engine)
        self.logger.info("Database tables created")
    
    def drop_tables(self):
        """Drop all tables (use with caution!)"""
        Base.metadata.drop_all(self.engine)
        self.logger.warning("Database tables dropped")
    
    def get_session(self) -> DBSession:
        """Get database session"""
        return self.SessionLocal()
    
    def __enter__(self):
        """Context manager entry"""
        self.session = self.get_session()
        return self.session
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type:
            self.session.rollback()
        else:
            self.session.commit()
        self.session.close()


# Global database instance
_database: Optional[Database] = None


def get_database(connection_string: Optional[str] = None) -> Database:
    """
    Get global database instance
    
    Args:
        connection_string: PostgreSQL connection string
        
    Returns:
        Database instance
    """
    global _database
    if _database is None:
        _database = Database(connection_string)
    return _database
