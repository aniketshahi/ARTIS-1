"""
ARTIS Nmap Agent
Automated network scanning and service enumeration using Nmap
"""

import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import uuid

from artis.core.logger import get_logger
from artis.core.config import get_config
from artis.core.message_bus import get_message_bus, RoutingKeys
from artis.core.database import get_database, Vulnerability


class NmapAgent:
    """
    Nmap scanning agent for asset discovery and service enumeration
    """
    
    # Scan profiles
    PROFILES = {
        'quick': '-sV -T4 -F',  # Fast service detection, top 100 ports
        'thorough': '-sV -sC -O -T3 -p-',  # All ports, scripts, OS detection
        'stealth': '-sS -T2 -f',  # SYN scan, slow timing, fragmented packets
    }
    
    def __init__(self):
        """Initialize Nmap agent"""
        self.logger = get_logger()
        self.config = get_config()
        self.message_bus = get_message_bus()
        self.db = get_database()
        
        # Get Nmap path from config
        self.nmap_path = self.config.get('tools.nmap.path', '/usr/bin/nmap')
        
        # Verify Nmap is installed
        if not Path(self.nmap_path).exists():
            self.logger.warning(f"Nmap not found at {self.nmap_path}")
    
    def scan(self, target: str, profile: str = 'thorough', output_dir: str = 'output') -> Dict[str, Any]:
        """
        Execute Nmap scan
        
        Args:
            target: Target IP, hostname, or CIDR range
            profile: Scan profile (quick, thorough, stealth)
            output_dir: Directory to save scan results
            
        Returns:
            Scan results dictionary
        """
        self.logger.info(f"Starting Nmap {profile} scan of {target}")
        self.logger.audit(action='nmap_scan_start', target=target, result='initiated', profile=profile)
        
        # Get scan options
        scan_options = self.PROFILES.get(profile, self.PROFILES['thorough'])
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_path / f"nmap_{target.replace('/', '_')}_{timestamp}"
        
        # Build Nmap command
        command = [
            self.nmap_path,
            *scan_options.split(),
            '-oX', f"{output_file}.xml",  # XML output
            '-oN', f"{output_file}.txt",  # Normal output
            target
        ]
        
        try:
            # Execute Nmap
            self.logger.debug(f"Executing: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                self.logger.error(f"Nmap scan failed: {result.stderr}")
                self.logger.audit(action='nmap_scan_complete', target=target, result='failed')
                return {'success': False, 'error': result.stderr}
            
            self.logger.info(f"Nmap scan completed: {output_file}.xml")
            self.logger.audit(action='nmap_scan_complete', target=target, result='success')
            
            # Parse results
            vulnerabilities = self.parse_xml(f"{output_file}.xml")
            
            # Store in database and publish to message bus
            self._process_results(vulnerabilities, target)
            
            return {
                'success': True,
                'output_file': str(output_file),
                'vulnerabilities_found': len(vulnerabilities)
            }
        
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timed out for {target}")
            self.logger.audit(action='nmap_scan_complete', target=target, result='timeout')
            return {'success': False, 'error': 'Scan timed out'}
        
        except Exception as e:
            self.logger.error(f"Nmap scan error: {str(e)}", exc_info=True)
            self.logger.audit(action='nmap_scan_complete', target=target, result='error')
            return {'success': False, 'error': str(e)}
    
    def parse_xml(self, xml_file: str) -> List[Dict[str, Any]]:
        """
        Parse Nmap XML output
        
        Args:
            xml_file: Path to Nmap XML file
            
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info(f"Parsing Nmap XML: {xml_file}")
        
        vulnerabilities = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Iterate through hosts
            for host in root.findall('host'):
                # Get host status
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Get IP address
                address = host.find('address')
                if address is None:
                    continue
                
                ip_addr = address.get('addr')
                
                # Get hostname
                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')
                
                # Get OS detection
                os_info = None
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        os_info = osmatch.get('name')
                
                # Iterate through ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        protocol = port.get('protocol')
                        
                        # Get port state
                        state = port.find('state')
                        if state is None or state.get('state') != 'open':
                            continue
                        
                        # Get service information
                        service = port.find('service')
                        if service is None:
                            continue
                        
                        service_name = service.get('name', 'unknown')
                        service_product = service.get('product', '')
                        service_version = service.get('version', '')
                        service_extrainfo = service.get('extrainfo', '')
                        
                        # Build service string
                        service_full = f"{service_product} {service_version}".strip()
                        if not service_full:
                            service_full = service_name
                        
                        # Check for potential vulnerabilities
                        # Look for outdated versions, known vulnerable services, etc.
                        vuln_indicators = self._check_vulnerability_indicators(
                            service_name, service_product, service_version
                        )
                        
                        if vuln_indicators:
                            for indicator in vuln_indicators:
                                vuln = {
                                    'id': str(uuid.uuid4()),
                                    'target_ip': ip_addr,
                                    'target_hostname': hostname,
                                    'target_port': int(port_id),
                                    'protocol': protocol,
                                    'service_name': service_name,
                                    'service_version': service_full,
                                    'os_info': os_info,
                                    'severity': indicator.get('severity', 'medium'),
                                    'description': indicator.get('description', f"Open {service_name} service detected"),
                                    'source_tool': 'nmap',
                                    'discovered_at': datetime.utcnow().isoformat(),
                                    'cve_id': indicator.get('cve_id'),
                                    'cvss_score': indicator.get('cvss_score'),
                                }
                                vulnerabilities.append(vuln)
                        else:
                            # Create generic finding for open service
                            vuln = {
                                'id': str(uuid.uuid4()),
                                'target_ip': ip_addr,
                                'target_hostname': hostname,
                                'target_port': int(port_id),
                                'protocol': protocol,
                                'service_name': service_name,
                                'service_version': service_full,
                                'os_info': os_info,
                                'severity': 'low',
                                'description': f"Open {service_name} service on port {port_id}/{protocol}",
                                'source_tool': 'nmap',
                                'discovered_at': datetime.utcnow().isoformat(),
                            }
                            vulnerabilities.append(vuln)
            
            self.logger.info(f"Parsed {len(vulnerabilities)} findings from Nmap scan")
            return vulnerabilities
        
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML: {str(e)}", exc_info=True)
            return []
    
    def _check_vulnerability_indicators(self, service_name: str, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Check for known vulnerability indicators
        
        Args:
            service_name: Service name
            product: Product name
            version: Version string
            
        Returns:
            List of vulnerability indicators
        """
        indicators = []
        
        # Known vulnerable services (simplified - in production, use CVE database)
        vulnerable_patterns = {
            'ftp': {
                'vsftpd 2.3.4': {
                    'severity': 'critical',
                    'cve_id': 'CVE-2011-2523',
                    'cvss_score': 10.0,
                    'description': 'vsftpd 2.3.4 backdoor vulnerability'
                }
            },
            'ssh': {
                'OpenSSH 7.2': {
                    'severity': 'medium',
                    'description': 'Outdated OpenSSH version detected'
                }
            },
            'http': {
                'Apache 2.2': {
                    'severity': 'high',
                    'description': 'Outdated Apache version with known vulnerabilities'
                }
            },
            'smb': {
                'Samba 3.': {
                    'severity': 'critical',
                    'cve_id': 'CVE-2017-7494',
                    'cvss_score': 10.0,
                    'description': 'Samba remote code execution vulnerability (SambaCry)'
                }
            },
        }
        
        # Check for matches
        service_lower = service_name.lower()
        if service_lower in vulnerable_patterns:
            for pattern, vuln_info in vulnerable_patterns[service_lower].items():
                if pattern.lower() in f"{product} {version}".lower():
                    indicators.append(vuln_info)
        
        # Check for common vulnerable ports
        return indicators
    
    def _process_results(self, vulnerabilities: List[Dict[str, Any]], target: str):
        """
        Process scan results: store in database and publish to message bus
        
        Args:
            vulnerabilities: List of vulnerabilities
            target: Scan target
        """
        self.logger.info(f"Processing {len(vulnerabilities)} Nmap findings")
        
        # Store in database
        stored_count = 0
        with self.db.get_session() as session:
            for vuln_data in vulnerabilities:
                try:
                    vuln = Vulnerability(
                        id=vuln_data['id'],
                        target_ip=vuln_data['target_ip'],
                        target_port=vuln_data.get('target_port'),
                        service_name=vuln_data.get('service_name'),
                        service_version=vuln_data.get('service_version'),
                        cve_id=vuln_data.get('cve_id'),
                        cvss_score=vuln_data.get('cvss_score'),
                        severity=vuln_data.get('severity', 'low'),
                        description=vuln_data.get('description'),
                        source_tool='nmap',
                        discovered_at=datetime.utcnow(),
                        stix_data=vuln_data  # Store full data as STIX
                    )
                    session.add(vuln)
                    stored_count += 1
                    
                    # Publish to message bus
                    self.message_bus.publish(RoutingKeys.VULN_NMAP, vuln_data)
                
                except Exception as e:
                    self.logger.error(f"Failed to store vulnerability: {str(e)}")
        
        self.logger.info(f"Stored {stored_count} vulnerabilities in database")
        self.logger.audit(
            action='nmap_results_processed',
            target=target,
            result='success',
            vulnerabilities_stored=stored_count
        )


# Convenience function
def scan_target(target: str, profile: str = 'thorough') -> Dict[str, Any]:
    """
    Convenience function to scan a target
    
    Args:
        target: Target IP, hostname, or CIDR
        profile: Scan profile
        
    Returns:
        Scan results
    """
    agent = NmapAgent()
    return agent.scan(target, profile)
