"""
ARTIS Workflow Engine
Orchestrates end-to-end "scan-to-shell" workflow
"""

import time
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

from artis.core.logger import get_logger
from artis.core.config import get_config
from artis.core.message_bus import get_message_bus, RoutingKeys
from artis.core.database import get_database, WorkflowState, Vulnerability, Exploit
from artis.modules.module_1_vuln_id.nmap_agent import NmapAgent
from artis.modules.module_2_exploit.mapper import VulnerabilityExploitMapper
from artis.modules.module_2_exploit.metasploit_client import MetasploitClient


class WorkflowStep(Enum):
    """Workflow steps"""
    INIT = "init"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    EXPLOIT_MAPPING = "exploit_mapping"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    COMPLETE = "complete"
    FAILED = "failed"


class WorkflowEngine:
    """
    Orchestrates automated penetration testing workflow
    """
    
    def __init__(self):
        """Initialize workflow engine"""
        self.logger = get_logger()
        self.config = get_config()
        self.message_bus = get_message_bus()
        self.db = get_database()
        
        # Initialize modules
        self.nmap_agent = NmapAgent()
        self.exploit_mapper = VulnerabilityExploitMapper()
        self.msf_client = MetasploitClient()
        
        # Workflow configuration
        self.max_retries = self.config.get('orchestration.max_retries', 3)
        self.retry_delay = self.config.get('orchestration.retry_delay', 10)
        self.exploit_timeout = self.config.get('orchestration.exploit_timeout', 300)
    
    def execute_workflow(
        self,
        target: str,
        scan_profile: str = 'thorough',
        auto_exploit: bool = True,
        max_exploits: int = 3
    ) -> Dict[str, Any]:
        """
        Execute complete scan-to-shell workflow
        
        Args:
            target: Target IP, hostname, or CIDR
            scan_profile: Nmap scan profile
            auto_exploit: Automatically exploit discovered vulnerabilities
            max_exploits: Maximum number of exploits to attempt per vulnerability
            
        Returns:
            Workflow results
        """
        workflow_id = str(uuid.uuid4())
        
        self.logger.info(f"Starting workflow {workflow_id} for target {target}")
        self.logger.audit(
            action='workflow_start',
            target=target,
            result='initiated',
            workflow_id=workflow_id
        )
        
        # Initialize workflow state
        workflow_state = self._init_workflow_state(workflow_id, target)
        
        try:
            # Step 1: Discovery (Nmap scan)
            self._update_workflow_state(workflow_state, WorkflowStep.DISCOVERY)
            scan_result = self._execute_discovery(target, scan_profile, workflow_state)
            
            if not scan_result.get('success'):
                raise Exception(f"Discovery failed: {scan_result.get('error')}")
            
            # Step 2: Exploit Mapping
            self._update_workflow_state(workflow_state, WorkflowStep.EXPLOIT_MAPPING)
            vulnerabilities = self._get_vulnerabilities(target)
            
            if not vulnerabilities:
                self.logger.warning(f"No vulnerabilities found for {target}")
                self._update_workflow_state(workflow_state, WorkflowStep.COMPLETE, status='completed')
                return {
                    'success': True,
                    'workflow_id': workflow_id,
                    'message': 'No vulnerabilities found',
                    'vulnerabilities': 0,
                    'sessions': 0
                }
            
            # Map vulnerabilities to exploits
            exploit_mapping = self._map_vulnerabilities_to_exploits(vulnerabilities, workflow_state)
            
            # Step 3: Exploitation (if auto_exploit enabled)
            sessions_created = []
            if auto_exploit:
                self._update_workflow_state(workflow_state, WorkflowStep.EXPLOITATION)
                sessions_created = self._execute_exploitation(
                    exploit_mapping,
                    max_exploits,
                    workflow_state
                )
            
            # Step 4: Complete
            self._update_workflow_state(workflow_state, WorkflowStep.COMPLETE, status='completed')
            
            result = {
                'success': True,
                'workflow_id': workflow_id,
                'target': target,
                'vulnerabilities_found': len(vulnerabilities),
                'exploits_mapped': sum(len(v['exploits']) for v in exploit_mapping),
                'sessions_created': len(sessions_created),
                'sessions': sessions_created
            }
            
            self.logger.info(f"Workflow {workflow_id} completed successfully")
            self.logger.audit(
                action='workflow_complete',
                target=target,
                result='success',
                workflow_id=workflow_id,
                sessions_created=len(sessions_created)
            )
            
            # Publish completion
            self.message_bus.publish(RoutingKeys.WORKFLOW_COMPLETE, result)
            
            return result
        
        except Exception as e:
            self.logger.error(f"Workflow {workflow_id} failed: {str(e)}", exc_info=True)
            self._update_workflow_state(workflow_state, WorkflowStep.FAILED, status='failed')
            
            self.logger.audit(
                action='workflow_complete',
                target=target,
                result='failed',
                workflow_id=workflow_id,
                error=str(e)
            )
            
            # Publish error
            self.message_bus.publish(RoutingKeys.WORKFLOW_ERROR, {
                'workflow_id': workflow_id,
                'target': target,
                'error': str(e)
            })
            
            return {
                'success': False,
                'workflow_id': workflow_id,
                'error': str(e)
            }
    
    def _init_workflow_state(self, workflow_id: str, target: str) -> WorkflowState:
        """Initialize workflow state in database"""
        with self.db.get_session() as session:
            workflow_state = WorkflowState(
                id=workflow_id,
                workflow_name='scan_to_shell',
                target=target,
                current_step=WorkflowStep.INIT.value,
                status='running',
                state_data={},
                started_at=datetime.utcnow()
            )
            session.add(workflow_state)
            session.commit()
            session.refresh(workflow_state)
            return workflow_state
    
    def _update_workflow_state(
        self,
        workflow_state: WorkflowState,
        step: WorkflowStep,
        status: str = 'running',
        data: Optional[Dict[str, Any]] = None
    ):
        """Update workflow state"""
        with self.db.get_session() as session:
            ws = session.query(WorkflowState).filter(WorkflowState.id == workflow_state.id).first()
            if ws:
                ws.current_step = step.value
                ws.status = status
                ws.updated_at = datetime.utcnow()
                
                if status == 'completed' or status == 'failed':
                    ws.completed_at = datetime.utcnow()
                
                if data:
                    ws.state_data.update(data)
                
                session.commit()
        
        self.logger.info(f"Workflow step: {step.value} ({status})")
    
    def _execute_discovery(
        self,
        target: str,
        scan_profile: str,
        workflow_state: WorkflowState
    ) -> Dict[str, Any]:
        """Execute discovery phase"""
        self.logger.info(f"Executing discovery: {target} ({scan_profile})")
        
        # Execute Nmap scan
        scan_result = self.nmap_agent.scan(target, scan_profile)
        
        # Update workflow state
        self._update_workflow_state(
            workflow_state,
            WorkflowStep.DISCOVERY,
            data={'scan_result': scan_result}
        )
        
        return scan_result
    
    def _get_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for target from database"""
        with self.db.get_session() as session:
            vulns = session.query(Vulnerability).filter(
                Vulnerability.target_ip == target
            ).all()
            
            return [v.to_dict() for v in vulns]
    
    def _map_vulnerabilities_to_exploits(
        self,
        vulnerabilities: List[Dict[str, Any]],
        workflow_state: WorkflowState
    ) -> List[Dict[str, Any]]:
        """Map vulnerabilities to exploits"""
        self.logger.info(f"Mapping {len(vulnerabilities)} vulnerabilities to exploits")
        
        exploit_mapping = []
        
        for vuln in vulnerabilities:
            # Map vulnerability to exploits
            exploits = self.exploit_mapper.map_vulnerability(vuln)
            
            exploit_mapping.append({
                'vulnerability': vuln,
                'exploits': exploits
            })
        
        # Update workflow state
        self._update_workflow_state(
            workflow_state,
            WorkflowStep.EXPLOIT_MAPPING,
            data={'exploit_mapping_count': len(exploit_mapping)}
        )
        
        return exploit_mapping
    
    def _execute_exploitation(
        self,
        exploit_mapping: List[Dict[str, Any]],
        max_exploits: int,
        workflow_state: WorkflowState
    ) -> List[Dict[str, Any]]:
        """Execute exploitation phase"""
        self.logger.info("Executing exploitation phase")
        
        sessions_created = []
        
        # Sort by vulnerability severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_mapping = sorted(
            exploit_mapping,
            key=lambda x: severity_order.get(x['vulnerability'].get('severity', 'low'), 999)
        )
        
        for mapping in sorted_mapping:
            vuln = mapping['vulnerability']
            exploits = mapping['exploits'][:max_exploits]  # Limit exploits to try
            
            if not exploits:
                continue
            
            self.logger.info(f"Attempting exploitation of {vuln.get('target_ip')}:{vuln.get('target_port')}")
            
            # Try each exploit
            for exploit in exploits:
                if exploit.get('source') != 'metasploit':
                    self.logger.debug(f"Skipping non-Metasploit exploit: {exploit.get('name')}")
                    continue
                
                try:
                    self.logger.info(f"Trying exploit: {exploit.get('name')}")
                    
                    result = self.msf_client.execute_exploit(
                        exploit_path=exploit.get('name'),
                        target_ip=vuln.get('target_ip'),
                        target_port=vuln.get('target_port')
                    )
                    
                    if result.get('success'):
                        self.logger.info(f"Exploitation successful! Session created: {result.get('session_id')}")
                        sessions_created.append(result)
                        break  # Stop trying exploits for this vulnerability
                    else:
                        self.logger.warning(f"Exploitation failed: {result.get('error')}")
                
                except Exception as e:
                    self.logger.error(f"Exploitation error: {str(e)}")
                    continue
            
            # Small delay between exploitation attempts
            time.sleep(2)
        
        # Update workflow state
        self._update_workflow_state(
            workflow_state,
            WorkflowStep.EXPLOITATION,
            data={'sessions_created': len(sessions_created)}
        )
        
        return sessions_created
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """
        Get workflow status
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            Workflow status
        """
        with self.db.get_session() as session:
            workflow = session.query(WorkflowState).filter(
                WorkflowState.id == workflow_id
            ).first()
            
            if workflow:
                return workflow.to_dict()
            return None
    
    def list_workflows(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all workflows
        
        Args:
            status: Optional status filter
            
        Returns:
            List of workflows
        """
        with self.db.get_session() as session:
            query = session.query(WorkflowState)
            
            if status:
                query = query.filter(WorkflowState.status == status)
            
            workflows = query.order_by(WorkflowState.started_at.desc()).all()
            return [w.to_dict() for w in workflows]


# Convenience function
def execute_workflow(target: str, **kwargs) -> Dict[str, Any]:
    """Execute workflow"""
    engine = WorkflowEngine()
    return engine.execute_workflow(target, **kwargs)
