"""
ARTIS CLI Output Formatting
Handles formatted output for CLI (tables, JSON, colors, etc.)
"""

import json
import sys
from typing import List, Dict, Any, Optional
from tabulate import tabulate
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform color support
init(autoreset=True)


class OutputFormatter:
    """Format and display output for ARTIS CLI"""
    
    def __init__(self, format_type: str = 'table', quiet: bool = False):
        """
        Initialize output formatter
        
        Args:
            format_type: Output format (table, json, csv, plain)
            quiet: Suppress non-essential output
        """
        self.format_type = format_type
        self.quiet = quiet
    
    def print_banner(self):
        """Print ARTIS ASCII banner"""
        if self.quiet:
            return
        
        banner = f"""{Fore.CYAN}
    ___    ____  ______  ______
   /   |  / __ \\/_  __/ /  _/ /
  / /| | / /_/ / / /    / / / /
 / ___ |/ _, _/ / /   _/ / /_/
/_/  |_/_/ |_| /_/   /___/(_)

{Fore.GREEN}Autonomous Red Teaming Integrated System{Style.RESET_ALL}
{Fore.YELLOW}Version 0.1.0 - Phase 1 MVP{Style.RESET_ALL}
{Fore.RED}⚠  Use only on authorized systems  ⚠{Style.RESET_ALL}
        """
        print(banner)
    
    def success(self, message: str):
        """Print success message"""
        if not self.quiet:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def info(self, message: str):
        """Print info message"""
        if not self.quiet:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {message}")
    
    def warning(self, message: str):
        """Print warning message"""
        if not self.quiet:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def error(self, message: str):
        """Print error message"""
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}", file=sys.stderr)
    
    def debug(self, message: str):
        """Print debug message"""
        if not self.quiet:
            print(f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {message}")
    
    def print_table(self, data: List[Dict[str, Any]], headers: Optional[List[str]] = None):
        """
        Print data as table
        
        Args:
            data: List of dictionaries
            headers: Optional custom headers
        """
        if not data:
            self.warning("No data to display")
            return
        
        if self.format_type == 'json':
            self.print_json(data)
        elif self.format_type == 'csv':
            self.print_csv(data)
        elif self.format_type == 'plain':
            self.print_plain(data)
        else:  # table (default)
            if headers is None:
                headers = list(data[0].keys())
            
            table_data = [[row.get(h, '') for h in headers] for row in data]
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
    
    def print_json(self, data: Any):
        """Print data as JSON"""
        print(json.dumps(data, indent=2, default=str))
    
    def print_csv(self, data: List[Dict[str, Any]]):
        """Print data as CSV"""
        if not data:
            return
        
        headers = list(data[0].keys())
        print(','.join(headers))
        
        for row in data:
            values = [str(row.get(h, '')) for h in headers]
            print(','.join(values))
    
    def print_plain(self, data: Any):
        """Print data as plain text"""
        if isinstance(data, list):
            for item in data:
                print(item)
        else:
            print(data)
    
    def print_vulnerability(self, vuln: Dict[str, Any]):
        """Print formatted vulnerability details"""
        severity_colors = {
            'critical': Fore.RED,
            'high': Fore.LIGHTRED_EX,
            'medium': Fore.YELLOW,
            'low': Fore.GREEN,
        }
        
        severity = vuln.get('severity', 'unknown').lower()
        color = severity_colors.get(severity, Fore.WHITE)
        
        print(f"\n{color}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Vulnerability ID:{Style.RESET_ALL} {vuln.get('id')}")
        print(f"{Fore.CYAN}CVE:{Style.RESET_ALL} {vuln.get('cve_id', 'N/A')}")
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {vuln.get('target_ip')}:{vuln.get('target_port', 'N/A')}")
        print(f"{Fore.CYAN}Service:{Style.RESET_ALL} {vuln.get('service_name', 'N/A')} {vuln.get('service_version', '')}")
        print(f"{Fore.CYAN}Severity:{Style.RESET_ALL} {color}{severity.upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}CVSS Score:{Style.RESET_ALL} {vuln.get('cvss_score', 'N/A')}")
        print(f"{Fore.CYAN}Source:{Style.RESET_ALL} {vuln.get('source_tool', 'N/A')}")
        print(f"{Fore.CYAN}Discovered:{Style.RESET_ALL} {vuln.get('discovered_at', 'N/A')}")
        print(f"{Fore.CYAN}Description:{Style.RESET_ALL}\n{vuln.get('description', 'No description available')}")
        print(f"{color}{'='*60}{Style.RESET_ALL}\n")
    
    def print_session(self, session: Dict[str, Any]):
        """Print formatted session details"""
        status_colors = {
            'active': Fore.GREEN,
            'dead': Fore.RED,
            'background': Fore.YELLOW,
        }
        
        status = session.get('session_status', 'unknown').lower()
        color = status_colors.get(status, Fore.WHITE)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Session ID:{Style.RESET_ALL} {session.get('id')}")
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {session.get('target_ip')} ({session.get('target_hostname', 'N/A')})")
        print(f"{Fore.CYAN}Framework:{Style.RESET_ALL} {session.get('c2_framework', 'N/A')}")
        print(f"{Fore.CYAN}Type:{Style.RESET_ALL} {session.get('session_type', 'N/A')}")
        print(f"{Fore.CYAN}Status:{Style.RESET_ALL} {color}{status.upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}User:{Style.RESET_ALL} {session.get('username', 'N/A')} ({session.get('privileges', 'N/A')})")
        print(f"{Fore.CYAN}Established:{Style.RESET_ALL} {session.get('established_at', 'N/A')}")
        print(f"{Fore.CYAN}Last Seen:{Style.RESET_ALL} {session.get('last_seen', 'N/A')}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def print_progress(self, message: str, current: int, total: int):
        """Print progress indicator"""
        if self.quiet:
            return
        
        percent = (current / total) * 100 if total > 0 else 0
        bar_length = 40
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\r{Fore.CYAN}[*]{Style.RESET_ALL} {message}: [{bar}] {percent:.1f}% ({current}/{total})", end='', flush=True)
        
        if current >= total:
            print()  # New line when complete
    
    def print_status(self, component: str, status: str, details: str = ""):
        """Print component status"""
        status_symbols = {
            'running': f"{Fore.GREEN}●{Style.RESET_ALL}",
            'stopped': f"{Fore.RED}●{Style.RESET_ALL}",
            'warning': f"{Fore.YELLOW}●{Style.RESET_ALL}",
            'unknown': f"{Fore.WHITE}●{Style.RESET_ALL}",
        }
        
        symbol = status_symbols.get(status.lower(), status_symbols['unknown'])
        print(f"{symbol} {Fore.CYAN}{component:20}{Style.RESET_ALL} {status:10} {details}")


# Global output formatter
_output_formatter: Optional[OutputFormatter] = None


def get_output_formatter(format_type: str = 'table', quiet: bool = False) -> OutputFormatter:
    """
    Get global output formatter instance
    
    Args:
        format_type: Output format
        quiet: Suppress non-essential output
        
    Returns:
        OutputFormatter instance
    """
    global _output_formatter
    if _output_formatter is None:
        _output_formatter = OutputFormatter(format_type, quiet)
    return _output_formatter
