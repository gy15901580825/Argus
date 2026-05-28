#!/bin/bash
# Deploy Argus services using Helm or kubectl
# Usage: ./deploy.sh [method] [service|all] [namespace]
#   method: helm (default) or kubectl
#   service: orchestrator, api_service, testing_api_service, or all
#   namespace: default (default)

set -e

METHOD="${1:-helm}"
SERVICE="${2:-all}"
NAMESPACE="${3:-default}"
CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/charts"
YAML_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rendered"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Argus Services Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Method: ${YELLOW}$METHOD${NC}"
echo -e "Service: ${YELLOW}$SERVICE${NC}"
echo -e "Namespace: ${YELLOW}$NAMESPACE${NC}"
echo ""

# Function to convert service name (replace underscore with hyphen)
normalize_service_name() {
    echo "$1" | tr '_' '-'
}

# Function to deploy using Helm
deploy_with_helm() {
    local service=$1
    local chart_name="${service}"
    local release_name="argus-$(normalize_service_name $service)"
    local chart_path="$CHART_DIR/$chart_name"
    
    if [ ! -d "$chart_path" ]; then
        echo -e "${RED}Error: Chart not found: $chart_path${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Deploying $service using Helm...${NC}"
    
    # Check if release exists
    if helm list -n "$NAMESPACE" | grep -q "$release_name"; then
        echo -e "${YELLOW}Release $release_name already exists. Upgrading...${NC}"
        helm upgrade "$release_name" "$chart_path" \
            --namespace "$NAMESPACE" \
            --create-namespace
    else
        echo -e "${GREEN}Installing new release $release_name...${NC}"
        helm install "$release_name" "$chart_path" \
            --namespace "$NAMESPACE" \
            --create-namespace
    fi
    
    echo -e "${GREEN}✓ $service deployed successfully${NC}"
}

# Function to render Helm chart and deploy with kubectl
deploy_with_kubectl() {
    local service=$1
    local chart_name="${service}"
    local release_name="argus-$(normalize_service_name $service)"
    local chart_path="$CHART_DIR/$chart_name"
    local output_dir="$YAML_DIR/$chart_name"
    
    if [ ! -d "$chart_path" ]; then
        echo -e "${RED}Error: Chart not found: $chart_path${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Rendering $service chart and deploying with kubectl...${NC}"
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Render Helm chart to YAML
    echo -e "${YELLOW}Rendering Helm chart...${NC}"
    helm template "$release_name" "$chart_path" \
        --namespace "$NAMESPACE" \
        > "$output_dir/rendered.yaml"
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply rendered YAML
    echo -e "${YELLOW}Applying rendered YAML...${NC}"
    kubectl apply -f "$output_dir/rendered.yaml" -n "$NAMESPACE"
    
    echo -e "${GREEN}✓ $service deployed successfully${NC}"
    echo -e "${YELLOW}Rendered YAML saved to: $output_dir/rendered.yaml${NC}"
}

# Function to deploy a service
deploy_service() {
    local service=$1
    
    case $service in
        orchestrator)
            if [ "$METHOD" == "helm" ]; then
                deploy_with_helm "orchestrator"
            else
                deploy_with_kubectl "orchestrator"
            fi
            ;;
        api_service)
            if [ "$METHOD" == "helm" ]; then
                deploy_with_helm "api_service"
            else
                deploy_with_kubectl "api_service"
            fi
            ;;
        testing_api_service)
            if [ "$METHOD" == "helm" ]; then
                deploy_with_helm "testing_api_service"
            else
                deploy_with_kubectl "testing_api_service"
            fi
            ;;
        testing_web_fetch_service)
            if [ "$METHOD" == "helm" ]; then
                deploy_with_helm "testing_web_fetch_service"
            else
                deploy_with_kubectl "testing_web_fetch_service"
            fi
            ;;
        *)
            echo -e "${RED}Unknown service: $service${NC}"
            return 1
            ;;
    esac
}

# Function to deploy all services
deploy_all() {
    echo -e "${GREEN}Deploying all services...${NC}"
    echo ""
    
    services=("orchestrator" "api_service" "testing_api_service" "testing_web_fetch_service")
    
    for service in "${services[@]}"; do
        echo -e "${BLUE}--- Deploying $service ---${NC}"
        deploy_service "$service"
        echo ""
    done
}

# Main deployment logic
if [ "$SERVICE" == "all" ]; then
    deploy_all
else
    deploy_service "$SERVICE"
fi

# Show deployment status
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Deployment Status${NC}"
echo -e "${BLUE}========================================${NC}"

if [ "$METHOD" == "helm" ]; then
    echo -e "${GREEN}Helm Releases:${NC}"
    helm list -n "$NAMESPACE" | grep -E "(NAME|argus)" || echo "  No releases found"
else
    echo -e "${GREEN}Deployed Resources:${NC}"
    kubectl get all -n "$NAMESPACE" -l app.kubernetes.io/name 2>/dev/null | grep -E "(NAME|argus)" || echo "  No resources found"
fi

echo ""
echo -e "${GREEN}Pods Status:${NC}"
kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name 2>/dev/null | grep -E "(NAME|argus)" || echo "  No pods found"

echo ""
echo -e "${GREEN}Services Status:${NC}"
kubectl get svc -n "$NAMESPACE" -l app.kubernetes.io/name 2>/dev/null | grep -E "(NAME|argus)" || echo "  No services found"

echo ""
echo -e "${GREEN}✓ Deployment completed!${NC}"
