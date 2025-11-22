"""
ARTIS CLI Parser
Main entry point for command-line interface
"""

import sys
import argparse
from typing import List, Optional
from artis.cli.output import get_output_formatter
from artis.cli.console import ARTISConsole
from artis.core.logger import get_logger, setup_logger
from artis.core.config import get_config
from artis import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for ARTIS CLI"""
    
    parser = argparse.ArgumentParser(
        prog='artis',
        description='ARTIS - Autonomous Red Teaming Integrated System',
        epilog='Use "artis <command> --help" for more information about a command.'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'ARTIS {__version__}'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--format',
        choices=['table', 'json', 'csv', 'plain'],
        default='table',
        help='Output format (default: table)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress non-essential output'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Console command (interactive mode)
    console_parser = subparsers.add_parser(
        'console',
        help='Start interactive console'
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Run vulnerability scans'
    )
    scan_parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target IP, hostname, or CIDR range'
    )
    scan_parser.add_argument(
        '-p', '--profile',
        choices=['quick', 'thorough', 'stealth'],
        default='thorough',
        help='Scan profile (default: thorough)'
    )
    scan_parser.add_argument(
        '--tool',
        choices=['nmap', 'nessus', 'zap', 'all'],
        default='all',
        help='Scanning tool to use (default: all)'
    )
    
    # Vulns command
    vulns_parser = subparsers.add_parser(
        'vulns',
        help='Manage vulnerabilities'
    )
    vulns_subparsers = vulns_parser.add_subparsers(dest='vulns_action')
    
    vulns_list = vulns_subparsers.add_parser('list', help='List vulnerabilities')
    vulns_list.add_argument(
        '--severity',
        choices=['low', 'medium', 'high', 'critical'],
        help='Filter by severity'
    )
    vulns_list.add_argument(
        '--target',
        help='Filter by target IP'
    )
    
    vulns_show = vulns_subparsers.add_parser('show', help='Show vulnerability details')
    vulns_show.add_argument('id', help='Vulnerability ID')
    
    # Exploit command
    exploit_parser = subparsers.add_parser(
        'exploit',
        help='Manage exploits'
    )
    exploit_subparsers = exploit_parser.add_subparsers(dest='exploit_action')
    
    exploit_search = exploit_subparsers.add_parser('search', help='Search for exploits')
    exploit_search.add_argument('query', help='CVE ID or search term')
    
    exploit_run = exploit_subparsers.add_parser('run', help='Run exploit')
    exploit_run.add_argument('id', help='Exploit ID')
    exploit_run.add_argument(
        '--payload',
        help='Payload type (default: auto-select)'
    )
    
    # Sessions command
    sessions_parser = subparsers.add_parser(
        'sessions',
        help='Manage C2 sessions'
    )
    sessions_subparsers = sessions_parser.add_subparsers(dest='sessions_action')
    
    sessions_list = sessions_subparsers.add_parser('list', help='List sessions')
    sessions_list.add_argument(
        '--status',
        choices=['active', 'dead', 'background'],
        help='Filter by status'
    )
    
    sessions_interact = sessions_subparsers.add_parser('interact', help='Interact with session')
    sessions_interact.add_argument('id', help='Session ID')
    
    sessions_kill = sessions_subparsers.add_parser('kill', help='Kill session')
    sessions_kill.add_argument('id', help='Session ID')
    
    # Workflow command
    workflow_parser = subparsers.add_parser(
        'workflow',
        help='Manage automated workflows'
    )
    workflow_subparsers = workflow_parser.add_subparsers(dest='workflow_action')
    
    workflow_start = workflow_subparsers.add_parser('start', help='Start workflow')
    workflow_start.add_argument(
        '-c', '--config',
        help='Workflow configuration file'
    )
    workflow_start.add_argument(
        '-o', '--output',
        help='Output report file'
    )
    
    workflow_status = workflow_subparsers.add_parser('status', help='Check workflow status')
    workflow_status.add_argument('id', nargs='?', help='Workflow ID (optional)')
    
    workflow_stop = workflow_subparsers.add_parser('stop', help='Stop workflow')
    workflow_stop.add_argument('id', help='Workflow ID')
    
    # Status command
    status_parser = subparsers.add_parser(
        'status',
        help='Show system status'
    )
    
    # Database command
    db_parser = subparsers.add_parser(
        'db',
        help='Database operations'
    )
    db_subparsers = db_parser.add_subparsers(dest='db_action')
    
    db_init = db_subparsers.add_parser('init', help='Initialize database')
    db_status = db_subparsers.add_parser('status', help='Database status')
    db_clear = db_subparsers.add_parser('clear', help='Clear all data (use with caution!)')
    
    return parser


def handle_command(args: argparse.Namespace) -> int:
    """
    Handle CLI command execution
    
    Args:
        args: Parsed arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Initialize output formatter
    output = get_output_formatter(args.format, args.quiet)
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logger(level=log_level)
    logger = get_logger()
    
    try:
        # Load configuration
        config = get_config(args.config if hasattr(args, 'config') and args.config else None)
        
        # Handle commands
        if args.command is None or args.command == 'console':
            # Start interactive console
            output.print_banner()
            console = ARTISConsole()
            console.cmdloop()
            return 0
        
        elif args.command == 'scan':
            output.info(f"Starting {args.profile} scan of {args.target} using {args.tool}")
            
            try:
                if args.tool == 'nmap' or args.tool == 'all':
                    from artis.modules.module_1_vuln_id.nmap_agent import scan_target
                    result = scan_target(args.target, args.profile)
                    
                    if result.get('success'):
                        output.success(f"Scan completed: {result.get('vulnerabilities_found')} findings")
                        output.info(f"Results saved to: {result.get('output_file')}")
                        return 0
                    else:
                        output.error(f"Scan failed: {result.get('error')}")
                        return 1
                else:
                    output.warning(f"Tool {args.tool} not yet implemented")
                    return 1
            except Exception as e:
                output.error(f"Scan error: {str(e)}")
                logger.error(f"Scan failed: {str(e)}", exc_info=True)
                return 1

        
        elif args.command == 'vulns':
            if args.vulns_action == 'list':
                output.info("Listing vulnerabilities...")
                # TODO: Implement vulns list
                output.warning("Vulns list command not yet implemented")
            elif args.vulns_action == 'show':
                output.info(f"Showing vulnerability {args.id}")
                # TODO: Implement vulns show
                output.warning("Vulns show command not yet implemented")
            return 1
        
        elif args.command == 'exploit':
            if args.exploit_action == 'search':
                output.info(f"Searching for exploits: {args.query}")
                # TODO: Implement exploit search
                output.warning("Exploit search command not yet implemented")
            elif args.exploit_action == 'run':
                output.info(f"Running exploit {args.id}")
                # TODO: Implement exploit run
                output.warning("Exploit run command not yet implemented")
            return 1
        
        elif args.command == 'sessions':
            if args.sessions_action == 'list':
                output.info("Listing sessions...")
                # TODO: Implement sessions list
                output.warning("Sessions list command not yet implemented")
            elif args.sessions_action == 'interact':
                output.info(f"Interacting with session {args.id}")
                # TODO: Implement sessions interact
                output.warning("Sessions interact command not yet implemented")
            elif args.sessions_action == 'kill':
                output.info(f"Killing session {args.id}")
                # TODO: Implement sessions kill
            return 1
        
        elif args.command == 'workflow':
            if args.workflow_action == 'start':
                output.info("Starting automated workflow...")
                
                try:
                    from artis.orchestration.workflow_engine import execute_workflow
                    
                    # Get target from config file or use default
                    target = None
                    if args.config:
                        import yaml
                        with open(args.config, 'r') as f:
                            config_data = yaml.safe_load(f)
                            targets = config_data.get('targets', [])
                            if targets:
                                target = targets[0].get('cidr') or targets[0].get('url')
                    
                    if not target:
                        output.error("No target specified. Use --config with targets.yaml")
                        return 1
                    
                    output.info(f"Target: {target}")
                    result = execute_workflow(target)
                    
                    if result.get('success'):
                        output.success(f"Workflow completed!")
                        output.info(f"Vulnerabilities found: {result.get('vulnerabilities_found', 0)}")
                        output.info(f"Sessions created: {result.get('sessions_created', 0)}")
                        
                        if args.output:
                            output.info(f"Report would be saved to: {args.output}")
                        
                        return 0
                    else:
                        output.error(f"Workflow failed: {result.get('error')}")
                        return 1
                
                except Exception as e:
                    output.error(f"Workflow error: {str(e)}")
                    logger.error(f"Workflow failed: {str(e)}", exc_info=True)
                    return 1
            
            elif args.workflow_action == 'status':
                try:
                    from artis.orchestration.workflow_engine import WorkflowEngine
                    engine = WorkflowEngine()
                    
                    if args.id:
                        status = engine.get_workflow_status(args.id)
                        if status:
                            output.print_json(status)
                        else:
                            output.error(f"Workflow not found: {args.id}")
                            return 1
                    else:
                        workflows = engine.list_workflows()
                        if workflows:
                            output.print_table(workflows, ['id', 'target', 'status', 'current_step', 'started_at'])
                        else:
                            output.warning("No workflows found")
                    
                    return 0
                
                except Exception as e:
                    output.error(f"Error: {str(e)}")
                    return 1
            
            elif args.workflow_action == 'stop':
                output.warning("Workflow stop not yet implemented")
                return 1
            
            return 1
        
        elif args.command == 'db':
            if args.db_action == 'init':
                output.info("Initializing database...")
                from artis.core.database import get_database
                db = get_database()
                db.create_tables()
                output.success("Database initialized successfully")
                return 0
            elif args.db_action == 'status':
                output.info("Checking database status...")
                # TODO: Implement db status
                output.warning("Database status command not yet implemented")
            elif args.db_action == 'clear':
                output.warning("This will delete ALL data from the database!")
                confirm = input("Type 'YES' to confirm: ")
                if confirm == 'YES':
                    from artis.core.database import get_database
                    db = get_database()
                    db.drop_tables()
                    db.create_tables()
                    output.success("Database cleared")
                else:
                    output.info("Operation cancelled")
                return 0
            return 1
        
        else:
            output.error(f"Unknown command: {args.command}")
            return 1
    
    except KeyboardInterrupt:
        output.warning("\nOperation cancelled by user")
        return 130
    except Exception as e:
        output.error(f"Error: {str(e)}")
        logger.error(f"Command execution failed: {str(e)}", exc_info=True)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for ARTIS CLI
    
    Args:
        argv: Command-line arguments (uses sys.argv if None)
        
    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # If no command specified, start interactive console
    if not hasattr(args, 'command') or args.command is None:
        args.command = 'console'
    
    return handle_command(args)


if __name__ == '__main__':
    sys.exit(main())
