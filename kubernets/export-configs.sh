#!/bin/bash
# Export APISIX and PostgreSQL configurations from Kubernetes cluster
# Usage: ./export-configs.sh [namespace]

set -e

NAMESPACE="${1:-default}"
YAMLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/yamls"
APISIX_DIR="$YAMLS_DIR/apisix"
POSTGRES_DIR="$YAMLS_DIR/postgresql"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Exporting Kubernetes Configurations${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Namespace: ${YELLOW}$NAMESPACE${NC}"
echo -e "Output Directory: ${YELLOW}$YAMLS_DIR${NC}"
echo ""

# Create directories
mkdir -p "$APISIX_DIR"
mkdir -p "$POSTGRES_DIR"

# Function to export resources
export_resource() {
    local resource_type=$1
    local resource_name=$2
    local output_file=$3
    local namespace=$4
    
    if kubectl get "$resource_type" "$resource_name" -n "$namespace" &>/dev/null; then
        echo -e "${GREEN}Exporting $resource_type/$resource_name...${NC}"
        kubectl get "$resource_type" "$resource_name" -n "$namespace" -o yaml > "$output_file"
        # Remove kubectl metadata
        sed -i '/^  creationTimestamp:/d' "$output_file"
        sed -i '/^  resourceVersion:/d' "$output_file"
        sed -i '/^  uid:/d' "$output_file"
        sed -i '/^  generation:/d' "$output_file"
        sed -i '/^  managedFields:/,/^  - /d' "$output_file"
        sed -i '/^status:/,$d' "$output_file"
        echo -e "  ${GREEN}✓${NC} Saved to: $output_file"
    else
        echo -e "${YELLOW}  ⚠ $resource_type/$resource_name not found in namespace $namespace${NC}"
    fi
}

# Function to export all resources of a type
export_all_resources() {
    local resource_type=$1
    local output_dir=$2
    local namespace=$3
    local label_selector=$4
    
    local resources
    if [ -n "$label_selector" ]; then
        resources=$(kubectl get "$resource_type" -n "$namespace" -l "$label_selector" -o name 2>/dev/null || echo "")
    else
        resources=$(kubectl get "$resource_type" -n "$namespace" -o name 2>/dev/null || echo "")
    fi
    
    if [ -z "$resources" ]; then
        echo -e "${YELLOW}No $resource_type found${NC}"
        return
    fi
    
    echo -e "${GREEN}Exporting all $resource_type...${NC}"
    while IFS= read -r resource; do
        if [ -n "$resource" ]; then
            local name=$(echo "$resource" | cut -d'/' -f2)
            local output_file="$output_dir/${resource_type}-${name}.yaml"
            export_resource "$resource_type" "$name" "$output_file" "$namespace"
        fi
    done <<< "$resources"
}

# Export APISIX resources
echo -e "${BLUE}--- Exporting APISIX Resources ---${NC}"

# Try to find APISIX by common labels/names
APISIX_NAMES=$(kubectl get all -n "$NAMESPACE" -o name 2>/dev/null | grep -i apisix || echo "")

if [ -n "$APISIX_NAMES" ]; then
    # Export APISIX Gateway resources
    export_all_resources "deployment" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix"
    export_all_resources "service" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix"
    export_all_resources "configmap" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix"
    export_all_resources "secret" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix"
    
    # Export APISIX Admin API
    export_all_resources "deployment" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix-dashboard"
    export_all_resources "service" "$APISIX_DIR" "$NAMESPACE" "app.kubernetes.io/name=apisix-dashboard"
    
    # Export Ingress resources (APISIX uses Ingress)
    export_all_resources "ingress" "$APISIX_DIR" "$NAMESPACE" ""
    
    # Try common APISIX resource names
    for name in apisix apisix-gateway apisix-dashboard apisix-admin; do
        export_resource "deployment" "$name" "$APISIX_DIR/deployment-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
        export_resource "service" "$name" "$APISIX_DIR/service-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
    done
else
    echo -e "${YELLOW}APISIX resources not found. Trying to find by common patterns...${NC}"
    # Try to find any gateway-like services
    kubectl get svc -n "$NAMESPACE" -o name | grep -iE "(gateway|apisix|ingress)" | while read -r svc; do
        name=$(echo "$svc" | cut -d'/' -f2)
        export_resource "service" "$name" "$APISIX_DIR/service-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
    done
fi

# Export PostgreSQL resources
echo -e "\n${BLUE}--- Exporting PostgreSQL Resources ---${NC}"

# Try to find PostgreSQL by common labels/names
export_all_resources "deployment" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"
export_all_resources "statefulset" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"
export_all_resources "service" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"
export_all_resources "configmap" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"
export_all_resources "secret" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"
export_all_resources "pvc" "$POSTGRES_DIR" "$NAMESPACE" "app.kubernetes.io/name=postgresql"

# Try common PostgreSQL resource names
for name in postgres postgresql postgres-db postgresql-db; do
    export_resource "deployment" "$name" "$POSTGRES_DIR/deployment-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
    export_resource "statefulset" "$name" "$POSTGRES_DIR/statefulset-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
    export_resource "service" "$name" "$POSTGRES_DIR/service-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
    export_resource "pvc" "$name" "$POSTGRES_DIR/pvc-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
done

# Export PersistentVolumeClaims for PostgreSQL
echo -e "${GREEN}Exporting PostgreSQL PVCs...${NC}"
kubectl get pvc -n "$NAMESPACE" -o name | grep -iE "(postgres|data)" | while read -r pvc; do
    name=$(echo "$pvc" | cut -d'/' -f2)
    export_resource "pvc" "$name" "$POSTGRES_DIR/pvc-${name}.yaml" "$NAMESPACE" 2>/dev/null || true
done

# Create summary
echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}Export Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "APISIX files: ${YELLOW}$(find "$APISIX_DIR" -name "*.yaml" 2>/dev/null | wc -l)${NC}"
echo -e "PostgreSQL files: ${YELLOW}$(find "$POSTGRES_DIR" -name "*.yaml" 2>/dev/null | wc -l)${NC}"
echo ""
echo -e "${GREEN}Files exported to:${NC}"
echo -e "  APISIX: ${YELLOW}$APISIX_DIR${NC}"
echo -e "  PostgreSQL: ${YELLOW}$POSTGRES_DIR${NC}"
echo ""
echo -e "${GREEN}✓ Export completed!${NC}"
