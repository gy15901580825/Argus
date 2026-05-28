#!/bin/bash
# Quick script to view deployment configurations
# Usage: ./view-deployment.sh [service_name|all]

set -e

K8S_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$K8S_DIR/charts"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_service_info() {
    local service=$1
    local chart_path="$CHART_DIR/${service}"
    
    if [ ! -d "$chart_path" ]; then
        echo -e "${RED}Error: Chart not found: $chart_path${NC}"
        return 1
    fi
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Service: $service${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Show Chart.yaml
    if [ -f "$chart_path/Chart.yaml" ]; then
        echo -e "\n${YELLOW}Chart Information:${NC}"
        cat "$chart_path/Chart.yaml"
    fi
    
    # Show values.yaml (key sections)
    if [ -f "$chart_path/values.yaml" ]; then
        echo -e "\n${YELLOW}Key Configuration (values.yaml):${NC}"
        echo -e "${GREEN}Image:${NC}"
        grep -A 3 "^image:" "$chart_path/values.yaml" || echo "  Not found"
        
        echo -e "\n${GREEN}Service Port:${NC}"
        grep -A 2 "^service:" "$chart_path/values.yaml" | grep "port:" || echo "  Not found"
        
        echo -e "\n${GREEN}Environment Variables:${NC}"
        grep -A 10 "^env:" "$chart_path/values.yaml" | head -15 || echo "  Not found"
        
        echo -e "\n${GREEN}Secrets Configuration:${NC}"
        grep -A 5 "^secrets:" "$chart_path/values.yaml" | head -10 || echo "  Not found"
    fi
    
    # Show deployment template key parts
    if [ -f "$chart_path/templates/deployment.yaml" ]; then
        echo -e "\n${YELLOW}Deployment Key Info:${NC}"
        echo -e "${GREEN}Container Port:${NC}"
        grep -A 2 "containerPort:" "$chart_path/templates/deployment.yaml" | head -3 || echo "  Not found"
        
        echo -e "\n${GREEN}Environment Variables from Secrets:${NC}"
        grep -B 2 -A 3 "secretKeyRef:" "$chart_path/templates/deployment.yaml" | head -20 || echo "  None found"
    fi
    
    echo ""
}

show_all_services() {
    echo -e "${GREEN}Available Services:${NC}"
    echo ""
    
    services=("orchestrator" "api_service" "testing_api_service")
    
    for service in "${services[@]}"; do
        show_service_info "$service"
    done
}

show_summary() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Argus Kubernetes Deployment Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo -e "${YELLOW}Directory Structure:${NC}"
    echo "  charts/              - Helm Charts (recommended)"
    echo "  yamls/               - Raw Kubernetes YAML files"
    echo ""
    echo -e "${YELLOW}Available Services:${NC}"
    echo "  1. orchestrator              - AI Agent Orchestrator (Port: 8081)"
    echo "  2. api_service               - API Service (Port: 8881)"
    echo "  3. testing_api_service       - Testing API Service (Port: 8000)"
    echo ""
    echo -e "${YELLOW}Quick Commands:${NC}"
    echo "  # View this help"
    echo "  ./view-deployment.sh"
    echo ""
    echo "  # View specific service"
    echo "  ./view-deployment.sh orchestrator"
    echo ""
    echo "  # View all services"
    echo "  ./view-deployment.sh all"
    echo ""
    echo "  # View rendered YAML (without deploying)"
    echo "  helm template release-name ./charts/orchestrator"
    echo ""
    echo "  # View actual deployed resources"
    echo "  kubectl get all -n default"
    echo ""
}

# Main
if [ -z "$1" ]; then
    show_summary
    exit 0
fi

SERVICE=$1

if [ "$SERVICE" == "all" ]; then
    show_all_services
elif [ "$SERVICE" == "help" ] || [ "$SERVICE" == "-h" ] || [ "$SERVICE" == "--help" ]; then
    show_summary
else
    show_service_info "$SERVICE"
fi
