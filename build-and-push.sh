#!/bin/bash
# Build and push Docker images to custom registry
# Usage: ./build-and-push.sh [service_name] [tag]
# Example: ./build-and-push.sh orchestrator 1.0.0

set -e

# REGISTRY="192.168.1.121:30500"
REGISTRY="<YOUR_ACR>.azurecr.io"
NAMESPACE="argus"
TAG="${2:-1.0.0}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to build and push a service
build_and_push() {
    local service=$1
    local service_dir="${service}"
    local old_image="<your-gh-user>/${service}:${TAG}"
    local new_image="${REGISTRY}/${NAMESPACE}/${service}:${TAG}"
    
    if [ ! -d "$service_dir" ]; then
        echo -e "${RED}Error: Directory $service_dir not found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Building $service...${NC}"
    cd "$service_dir"

    # Build the image
    echo -e "${YELLOW}Building image: $new_image${NC}"
    # Frontend bakes NEXT_PUBLIC_API_URL at build time. Override via env for dev builds:
    #   FRONTEND_API_URL=https://dev.example.com ./build-and-push.sh frontend dev-<sha>
    if [ "$service" = "frontend" ] && [ -n "$FRONTEND_API_URL" ]; then
        echo -e "${YELLOW}Using NEXT_PUBLIC_API_URL=$FRONTEND_API_URL${NC}"
        docker build --network=host --build-arg "NEXT_PUBLIC_API_URL=$FRONTEND_API_URL" -t "$new_image" .
    else
        docker build --network=host -t "$new_image" .
    fi
    
    # Tag the old image if it exists (for migration)
    if docker images "$old_image" --format "{{.Repository}}:{{.Tag}}" | grep -q "$old_image"; then
        echo -e "${YELLOW}Tagging old image: $old_image -> $new_image${NC}"
        docker tag "$old_image" "$new_image"
    fi
    
    # Push to registry
    echo -e "${GREEN}Pushing $new_image to registry...${NC}"
    docker push "$new_image"
    
    echo -e "${GREEN}✓ Successfully built and pushed $new_image${NC}"
    cd ..
}

# Function to build and push all services
build_all() {
    echo -e "${GREEN}Building and pushing all services...${NC}"
    
    services=("orchestrator" "api_service" "client_agent" "frontend" "demo_target")

    for service in "${services[@]}"; do
        # Map service names to directory names
        case $service in
            "orchestrator")
                build_and_push "orchestrator"
                ;;
            "api_service")
                build_and_push "api_service"
                ;;
            "client_agent")
                build_and_push "client_agent"
                ;;
            "frontend")
                build_and_push "frontend"
                ;;
            "demo_target")
                build_and_push "demo_target"
                ;;
            *)
                echo -e "${RED}Unknown service: $service${NC}"
                ;;
        esac
    done
}

# Legacy testing_* services moved to separate repos:
#   github.com/gy15901580825/argus-api-testing
#   github.com/gy15901580825/argus-web-ui-testing

# Main
if [ -z "$1" ]; then
    echo "Usage: $0 [service_name|all] [tag]"
    echo ""
    echo "Services:"
    echo "  orchestrator"
    echo "  api_service"
    echo "  client_agent"
    echo "  frontend"
    echo "  demo_target"
    echo "  all (build and push all services)"
    echo ""
    echo "Examples:"
    echo "  $0 orchestrator 1.0.0"
    echo "  $0 all 1.0.0"
    exit 1
fi

SERVICE=$1

if [ "$SERVICE" == "all" ]; then
    build_all
else
    build_and_push "$SERVICE"
fi

echo -e "${GREEN}Done!${NC}"
