"""
ARTIS Interactive Console
msfconsole-style interactive interface
"""

import cmd2
from cmd2 import with_argparser
import argparse
from typing import List, Dict, Any
from artis.cli.output import get_output_formatter
from artis.core.logger import get_logger
from artis.core.config import get_config
from artis.core.database import get_database, Vulnerability, Session
from artis import __version__


class ARTISConsole(cmd2.Cmd):
    """Interactive console for ARTIS"""
    
    intro = ""
    prompt = f"artis> "
    
    def __init__(self, *args, **kwargs):
        """Initialize console"""
        super().__init__(*args, **kwargs)
        
        # Remove default cmd2 commands we don't need
        self.hidden_commands.extend(['alias', 'macro', 'run_pyscript', 'run_script', 'shell'])
        
        # Initialize components
        self.output = get_output_formatter()
        self.logger = get_logger()
        self.config = get_config()
        self.db = get_database()
        
        # Print banner
        self.output.print_banner()
        self.output.info("Type 'help' for available commands")
        self.output.info("Type 'exit' to quit\n")
    
    # ========== Scan Commands ==========
    
    scan_parser = argparse.ArgumentParser()
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP, hostname, or CIDR')
    scan_parser.add_argument('-p', '--profile', choices=['quick', 'thorough', 'stealth'], default='thorough')
    scan_parser.add_argument('--tool', choices=['nmap', 'nessus', 'zap', 'all'], default='all')
    
    @with_argparser(scan_parser)
    def do_scan(self, args):
        """Run vulnerability scan"""
        self.output.info(f"Starting {args.profile} scan of {args.target} using {args.tool}")
        
        try:
            if args.tool == 'nmap' or args.tool == 'all':
                from artis.modules.module_1_vuln_id.nmap_agent import scan_target
                result = scan_target(args.target, args.profile)
                
                if result.get('success'):
                    self.output.success(f"Scan completed: {result.get('vulnerabilities_found')} findings")
                    self.output.info(f"Results saved to: {result.get('output_file')}")
                else:
                    self.output.error(f"Scan failed: {result.get('error')}")
            else:
                self.output.warning(f"Tool {args.tool} not yet implemented")
        
        except Exception as e:
            self.output.error(f"Scan error: {str(e)}")
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)

    
    # ========== Vulnerability Commands ==========
    
    vulns_parser = argparse.ArgumentParser()
    vulns_subparsers = vulns_parser.add_subparsers(dest='action', help='Vulnerability actions')
    
    vulns_list_parser = vulns_subparsers.add_parser('list', help='List vulnerabilities')
    vulns_list_parser.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'])
    vulns_list_parser.add_argument('--target', help='Filter by target IP')
    vulns_list_parser.add_argument('--limit', type=int, default=50, help='Max results')
    
    vulns_show_parser = vulns_subparsers.add_parser('show', help='Show vulnerability details')
    vulns_show_parser.add_argument('id', help='Vulnerability ID')
    
    @with_argparser(vulns_parser)
    def do_vulns(self, args):
        """Manage vulnerabilities"""
        if args.action == 'list':
            self._list_vulnerabilities(args.severity, args.target, args.limit)
        elif args.action == 'show':
            self._show_vulnerability(args.id)
        else:
            self.output.error("Invalid action. Use 'vulns list' or 'vulns show <id>'")
    
    def _list_vulnerabilities(self, severity: str = None, target: str = None, limit: int = 50):
        """List vulnerabilities from database"""
        try:
            with self.db.get_session() as session:
                query = session.query(Vulnerability)
                
                if severity:
                    query = query.filter(Vulnerability.severity == severity)
                if target:
                    query = query.filter(Vulnerability.target_ip == target)
                
                vulns = query.limit(limit).all()
                
                if not vulns:
                    self.output.warning("No vulnerabilities found")
                    return
                
                # Convert to dict for display
                vuln_data = [v.to_dict() for v in vulns]
                
                # Display as table
                headers = ['id', 'target_ip', 'target_port', 'cve_id', 'severity', 'cvss_score', 'source_tool']
                self.output.print_table(vuln_data, headers)
                
                self.output.success(f"Found {len(vulns)} vulnerabilities")
        
        except Exception as e:
            self.output.error(f"Failed to list vulnerabilities: {str(e)}")
            self.logger.error(f"Vulnerability list error: {str(e)}", exc_info=True)
    
    def _show_vulnerability(self, vuln_id: str):
        """Show detailed vulnerability information"""
        try:
            with self.db.get_session() as session:
                vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
                
                if not vuln:
                    self.output.error(f"Vulnerability not found: {vuln_id}")
                    return
                
                self.output.print_vulnerability(vuln.to_dict())
        
        except Exception as e:
            self.output.error(f"Failed to show vulnerability: {str(e)}")
            self.logger.error(f"Vulnerability show error: {str(e)}", exc_info=True)
    
    # ========== Exploit Commands ==========
    
    exploit_parser = argparse.ArgumentParser()
    exploit_subparsers = exploit_parser.add_subparsers(dest='action', help='Exploit actions')
    
    exploit_search_parser = exploit_subparsers.add_parser('search', help='Search for exploits')
    exploit_search_parser.add_argument('query', help='CVE ID or search term')
    
    exploit_run_parser = exploit_subparsers.add_parser('run', help='Run exploit')
    exploit_run_parser.add_argument('id', help='Exploit ID')
    exploit_run_parser.add_argument('--payload', help='Payload type')
    
    @with_argparser(exploit_parser)
    def do_exploit(self, args):
        """Manage exploits"""
        if args.action == 'search':
            self.output.info(f"Searching for exploits: {args.query}")
            # TODO: Implement exploit search
            self.output.warning("Exploit search not yet implemented")
        elif args.action == 'run':
            self.output.info(f"Running exploit {args.id}")
            # TODO: Implement exploit execution
            self.output.warning("Exploit execution not yet implemented")
        else:
            self.output.error("Invalid action. Use 'exploit search <query>' or 'exploit run <id>'")
    
    # ========== Session Commands ==========
    
    sessions_parser = argparse.ArgumentParser()
    sessions_subparsers = sessions_parser.add_subparsers(dest='action', help='Session actions')
    
    sessions_list_parser = sessions_subparsers.add_parser('list', help='List sessions')
    sessions_list_parser.add_argument('--status', choices=['active', 'dead', 'background'])
    
    sessions_interact_parser = sessions_subparsers.add_parser('interact', help='Interact with session')
    sessions_interact_parser.add_argument('id', help='Session ID')
    
    sessions_kill_parser = sessions_subparsers.add_parser('kill', help='Kill session')
    sessions_kill_parser.add_argument('id', help='Session ID')
    
    @with_argparser(sessions_parser)
    def do_sessions(self, args):
        """Manage C2 sessions"""
        if args.action == 'list':
            self._list_sessions(args.status)
        elif args.action == 'interact':
            self.output.info(f"Interacting with session {args.id}")
            # TODO: Implement session interaction
            self.output.warning("Session interaction not yet implemented")
        elif args.action == 'kill':
            self.output.info(f"Killing session {args.id}")
            # TODO: Implement session kill
            self.output.warning("Session kill not yet implemented")
        else:
            self.output.error("Invalid action. Use 'sessions list', 'sessions interact <id>', or 'sessions kill <id>'")
    
    def _list_sessions(self, status: str = None):
        """List C2 sessions from database"""
        try:
            with self.db.get_session() as session:
                query = session.query(Session)
                
                if status:
                    query = query.filter(Session.session_status == status)
                
                sessions = query.all()
                
                if not sessions:
                    self.output.warning("No sessions found")
                    return
                
                # Convert to dict for display
                session_data = [s.to_dict() for s in sessions]
                
                # Display as table
                headers = ['id', 'target_ip', 'c2_framework', 'session_type', 'session_status', 'username', 'established_at']
                self.output.print_table(session_data, headers)
                
                self.output.success(f"Found {len(sessions)} sessions")
        
        except Exception as e:
            self.output.error(f"Failed to list sessions: {str(e)}")
            self.logger.error(f"Session list error: {str(e)}", exc_info=True)
    
    # ========== Workflow Commands ==========
    
    workflow_parser = argparse.ArgumentParser()
    workflow_subparsers = workflow_parser.add_subparsers(dest='action', help='Workflow actions')
    
    workflow_start_parser = workflow_subparsers.add_parser('start', help='Start workflow')
    workflow_start_parser.add_argument('-c', '--config', help='Workflow config file')
    workflow_start_parser.add_argument('-o', '--output', help='Output report file')
    
    workflow_status_parser = workflow_subparsers.add_parser('status', help='Check workflow status')
    workflow_status_parser.add_argument('id', nargs='?', help='Workflow ID')
    
    workflow_stop_parser = workflow_subparsers.add_parser('stop', help='Stop workflow')
    workflow_stop_parser.add_argument('id', help='Workflow ID')
    
    @with_argparser(workflow_parser)
    def do_workflow(self, args):
        """Manage automated workflows"""
        if args.action == 'start':
            self.output.info("Starting automated workflow...")
            
            try:
                from artis.orchestration.workflow_engine import execute_workflow
                
                # Get target from config or prompt
                target = None
                if args.config:
                    import yaml
                    with open(args.config, 'r') as f:
                        config_data = yaml.safe_load(f)
                        targets = config_data.get('targets', [])
                        if targets:
                            target = targets[0].get('cidr') or targets[0].get('url')
                
                if not target:
                    target = input("Enter target (IP/CIDR): ")
                
                self.output.info(f"Executing workflow for target: {target}")
                result = execute_workflow(target)
                
                if result.get('success'):
                    self.output.success("Workflow completed!")
                    self.output.info(f"Vulnerabilities: {result.get('vulnerabilities_found', 0)}")
                    self.output.info(f"Sessions created: {result.get('sessions_created', 0)}")
                else:
                    self.output.error(f"Workflow failed: {result.get('error')}")
            
            except Exception as e:
                self.output.error(f"Workflow error: {str(e)}")
                self.logger.error(f"Workflow failed: {str(e)}", exc_info=True)
        
        elif args.action == 'status':
            try:
                from artis.orchestration.workflow_engine import WorkflowEngine
                engine = WorkflowEngine()
                
                if args.id:
                    status = engine.get_workflow_status(args.id)
                    if status:
                        self.output.print_json(status)
                    else:
                        self.output.error(f"Workflow not found: {args.id}")
                else:
                    workflows = engine.list_workflows()
                    if workflows:
                        self.output.print_table(workflows, ['id', 'target', 'status', 'current_step'])
                    else:
                        self.output.warning("No workflows found")
            
            except Exception as e:
                self.output.error(f"Error: {str(e)}")
        
        elif args.action == 'stop':
            self.output.warning("Workflow stop not yet implemented")
        else:
            self.output.error("Invalid action. Use 'workflow start', 'workflow status', or 'workflow stop <id>'")
    
    # ========== Database Commands ==========
    
    def do_db(self, args):
        """Database operations"""
        if args == 'status':
            self.output.info("Checking database status...")
            # TODO: Implement db status
            self.output.warning("Database status not yet implemented")
        elif args == 'init':
            self.output.info("Initializing database...")
            try:
                self.db.create_tables()
                self.output.success("Database initialized successfully")
            except Exception as e:
                self.output.error(f"Failed to initialize database: {str(e)}")
        else:
            self.output.error("Invalid action. Use 'db status' or 'db init'")
    
    # ========== Status Command ==========
    
    def do_status(self, args):
        """Show system status"""
        self.output.info("System Status:\n")
        
        # Check message bus
        try:
            from artis.core.message_bus import get_message_bus
            mb = get_message_bus()
            if mb.connection and not mb.connection.is_closed:
                self.output.print_status("Message Bus", "running", "RabbitMQ connected")
            else:
                self.output.print_status("Message Bus", "stopped", "Not connected")
        except Exception as e:
            self.output.print_status("Message Bus", "warning", str(e))
        
        # Check database
        try:
            with self.db.get_session() as session:
                vuln_count = session.query(Vulnerability).count()
                session_count = session.query(Session).count()
                self.output.print_status("Database", "running", f"{vuln_count} vulns, {session_count} sessions")
        except Exception as e:
            self.output.print_status("Database", "warning", str(e))
        
        # Configuration
        self.output.print_status("Configuration", "running", f"Loaded from {self.config.config_path}")
    
    # ========== Info Command ==========
    
    def do_info(self, args):
        """Show ARTIS information"""
        self.output.print_banner()
        print(f"Configuration: {self.config.config_path}")
        print(f"Database: {self.config.get('database.database')}")
        print(f"Message Bus: {self.config.get('message_bus.host')}:{self.config.get('message_bus.port')}")
    
    # ========== Exit Command ==========
    
    def do_exit(self, args):
        """Exit ARTIS console"""
        self.output.info("Goodbye!")
        return True
    
    # Alias for exit
    do_quit = do_exit
