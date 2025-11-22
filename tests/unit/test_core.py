"""
ARTIS Unit Tests
Tests for core infrastructure components
"""

import pytest
import tempfile
import os
from pathlib import Path

# Test configuration
def test_config_loading():
    """Test configuration loading"""
    from artis.core.config import Config
    
    # Create temporary config file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""
message_bus:
  host: localhost
  port: 5672

database:
  host: localhost
  port: 5432
  database: test_artis
""")
        config_path = f.name
    
    try:
        config = Config(config_path)
        assert config.get('message_bus.host') == 'localhost'
        assert config.get('message_bus.port') == 5672
        assert config.get('database.database') == 'test_artis'
    finally:
        os.unlink(config_path)


def test_config_env_override():
    """Test environment variable override"""
    from artis.core.config import Config
    
    os.environ['ARTIS_DB_HOST'] = 'testhost'
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("""
database:
  host: localhost
""")
        config_path = f.name
    
    try:
        config = Config(config_path)
        assert config.get('database.host') == 'testhost'
    finally:
        os.unlink(config_path)
        del os.environ['ARTIS_DB_HOST']


# Test logging
def test_logger_creation():
    """Test logger creation"""
    from artis.core.logger import ARTISLogger
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, 'test.log')
        logger = ARTISLogger('test', log_file, 'INFO')
        
        logger.info("Test message")
        logger.audit(action='test', target='127.0.0.1', result='success')
        
        assert os.path.exists(log_file)


# Test database models
def test_vulnerability_model():
    """Test Vulnerability model"""
    from artis.core.database import Vulnerability
    from datetime import datetime
    import uuid
    
    vuln = Vulnerability(
        id=str(uuid.uuid4()),
        target_ip='192.168.1.1',
        target_port=80,
        service_name='http',
        cve_id='CVE-2021-1234',
        cvss_score=7.5,
        severity='high',
        description='Test vulnerability',
        source_tool='nmap',
        discovered_at=datetime.utcnow()
    )
    
    assert vuln.target_ip == '192.168.1.1'
    assert vuln.severity == 'high'
    
    vuln_dict = vuln.to_dict()
    assert vuln_dict['target_ip'] == '192.168.1.1'
    assert vuln_dict['cve_id'] == 'CVE-2021-1234'


# Test Nmap agent
def test_nmap_vulnerability_detection():
    """Test Nmap vulnerability detection logic"""
    from artis.modules.module_1_vuln_id.nmap_agent import NmapAgent
    
    agent = NmapAgent()
    
    # Test vulnerability indicator detection
    indicators = agent._check_vulnerability_indicators('ftp', 'vsftpd', '2.3.4')
    assert len(indicators) > 0
    assert indicators[0]['severity'] == 'critical'


# Test exploit ranking
def test_exploit_ranking():
    """Test exploit ranking algorithm"""
    from artis.modules.module_2_exploit.exploitdb_search import ExploitDBSearch
    
    searcher = ExploitDBSearch()
    
    exploits = [
        {'title': 'Test 1', 'verified': True, 'date': '2023-01-01', 'platform': 'windows'},
        {'title': 'Test 2', 'verified': False, 'date': '2020-01-01', 'platform': 'linux'},
    ]
    
    ranked = searcher.rank_exploits(exploits)
    
    # Verified exploit should rank higher
    assert ranked[0]['verified'] == True
    assert ranked[0]['rank'] == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
