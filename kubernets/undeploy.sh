#!/bin/bash
# Undeploy Argus services
# Usage: ./undeploy.sh [method] [service|all] [namespace]
#   method: helm (default) or kubectl
#   service: orchestrator, api_service, or all
#   namespace: default (default)

set -e

METHOD="${1:-helm}"
SERVICE="${2:-all}"
NAMESPACE="${3:-default}"
YAML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rendered"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Argus Services Undeployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Method: ${YELLOW}$METHOD${NC}"
echo -e "Service: ${YELLOW}$SERVICE${NC}"
echo -e "Namespace: ${YELLOW}$NAMESPACE${NC}"
echo ""

# Function to convert service name (replace underscore with hyphen)
normalize_service_name() {
    echo "$1" | tr '_' '-'
}

# Function to undeploy using Helm
undeploy_with_helm() {
    local service=$1
    local release_name="argus-$(normalize_service_name $service)"
    
    if helm list -n "$NAMESPACE" | grep -q "$release_name"; then
        echo -e "${GREEN}Uninstalling $release_name...${NC}"
        helm uninstall "$release_name" -n "$NAMESPACE"
        echo -e "${GREEN}✓ $service uninstalled successfully${NC}"
    else
        echo -e "${YELLOW}Release $release_name not found${NC}"
    fi
}

# Function to undeploy using kubectl
undeploy_with_kubectl() {
    local service=$1
    local chart_name="${service}"
    local output_dir="$YAML_DIR/$chart_name"
    
    if [ -f "$output_dir/rendered.yaml" ]; then
        echo -e "${GREEN}Deleting resources from rendered YAML...${NC}"
        kubectl delete -f "$output_dir/rendered.yaml" -n "$NAMESPACE" --ignore-not-found=true
        echo -e "${GREEN}✓ $service undeployed successfully${NC}"
    else
        echo -e "${YELLOW}Rendered YAML not found: $output_dir/rendered.yaml${NC}"
        echo -e "${YELLOW}Attempting to delete by labels...${NC}"
        local normalized_name=$(normalize_service_name $service)
        kubectl delete all -n "$NAMESPACE" -l app.kubernetes.io/name=argus-${normalized_name} --ignore-not-found=true
    fi
}

# Function to undeploy a service
undeploy_service() {
    local service=$1
    
    case $service in
        orchestrator)
            if [ "$METHOD" == "helm" ]; then
                undeploy_with_helm "orchestrator"
            else
                undeploy_with_kubectl "orchestrator"
            fi
            ;;
        api_service)
            if [ "$METHOD" == "helm" ]; then
                undeploy_with_helm "api_service"
            else
                undeploy_with_kubectl "api_service"
            fi
            ;;
        *)
            echo -e "${RED}Unknown service: $service${NC}"
            return 1
            ;;
    esac
}

# Function to undeploy all services
undeploy_all() {
    echo -e "${GREEN}Undeploying all services...${NC}"
    echo ""

    # Note: testing_* services live in their own repos now —
    #   github.com/gy15901580825/argus-api-testing
    #   github.com/gy15901580825/argus-web-ui-testing
    # Run helm uninstall on each release in those repos to clean them up.
    services=("orchestrator" "api_service")
    
    for service in "${services[@]}"; do
        echo -e "${BLUE}--- Undeploying $service ---${NC}"
        undeploy_service "$service"
        echo ""
    done
}

# Main undeployment logic
if [ "$SERVICE" == "all" ]; then
    undeploy_all
else
    undeploy_service "$SERVICE"
fi

echo -e "${GREEN}✓ Undeployment completed!${NC}"
