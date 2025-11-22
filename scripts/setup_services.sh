#!/bin/bash
# ARTIS Service Management Script
# Start/stop/restart ARTIS services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Service status check
check_service() {
    local service=$1
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}●${NC} $service is running"
        return 0
    else
        echo -e "${RED}●${NC} $service is stopped"
        return 1
    fi
}

# Start services
start_services() {
    echo "Starting ARTIS services..."
    
    echo -n "Starting RabbitMQ... "
    sudo systemctl start rabbitmq-server
    echo -e "${GREEN}✓${NC}"
    
    echo -n "Starting PostgreSQL... "
    sudo systemctl start postgresql
    echo -e "${GREEN}✓${NC}"
    
    echo -n "Starting Metasploit RPC... "
    pkill msfrpcd 2>/dev/null || true
    sleep 1
    msfrpcd -P msf -S -a 127.0.0.1 &
    sleep 2
    echo -e "${GREEN}✓${NC}"
    
    echo ""
    echo -e "${GREEN}All services started successfully!${NC}"
}

# Stop services
stop_services() {
    echo "Stopping ARTIS services..."
    
    echo -n "Stopping Metasploit RPC... "
    pkill msfrpcd 2>/dev/null || true
    echo -e "${GREEN}✓${NC}"
    
    echo -n "Stopping RabbitMQ... "
    sudo systemctl stop rabbitmq-server
    echo -e "${GREEN}✓${NC}"
    
    echo -n "Stopping PostgreSQL... "
    sudo systemctl stop postgresql
    echo -e "${GREEN}✓${NC}"
    
    echo ""
    echo -e "${GREEN}All services stopped successfully!${NC}"
}

# Restart services
restart_services() {
    stop_services
    sleep 2
    start_services
}

# Check status
status_services() {
    echo "ARTIS Service Status:"
    echo "===================="
    check_service rabbitmq-server
    check_service postgresql
    
    if pgrep -x msfrpcd > /dev/null; then
        echo -e "${GREEN}●${NC} msfrpcd is running"
    else
        echo -e "${RED}●${NC} msfrpcd is stopped"
    fi
    
    echo ""
    echo "Database Connection:"
    if psql -h localhost -U artis -d artis -c "SELECT 1" > /dev/null 2>&1; then
        echo -e "${GREEN}●${NC} Database is accessible"
    else
        echo -e "${RED}●${NC} Database connection failed"
    fi
    
    echo ""
    echo "RabbitMQ Connection:"
    if sudo rabbitmqctl status > /dev/null 2>&1; then
        echo -e "${GREEN}●${NC} RabbitMQ is accessible"
    else
        echo -e "${RED}●${NC} RabbitMQ connection failed"
    fi
}

# Show usage
usage() {
    echo "Usage: $0 {start|stop|restart|status}"
    echo ""
    echo "Commands:"
    echo "  start   - Start all ARTIS services"
    echo "  stop    - Stop all ARTIS services"
    echo "  restart - Restart all ARTIS services"
    echo "  status  - Check status of all services"
    exit 1
}

# Main
case "$1" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    status)
        status_services
        ;;
    *)
        usage
        ;;
esac
