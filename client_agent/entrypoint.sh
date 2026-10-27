#!/bin/bash
set -e

ORCHESTRATOR_URL=${ORCHESTRATOR_URL:-}
API_SERVICE_URL=${API_SERVICE_URL:-}
AGENT_NAME=${AGENT_NAME:-default-client-agent}
USERNAME=${USERNAME:-}
PASSWORD=${PASSWORD:-}
API_TOKEN=${API_TOKEN:-}

if [ -z "$ORCHESTRATOR_URL" ]; then
    echo "Error: ORCHESTRATOR_URL must be set (e.g. ws://orchestrator:8080)"
    exit 1
fi

CMD_ARGS="--orchestrator-url $ORCHESTRATOR_URL --agent-name $AGENT_NAME"

# Without API_SERVICE_URL the agent connects to the orchestrator directly.
if [ -n "$API_SERVICE_URL" ]; then
    if [ -z "$API_TOKEN" ] && { [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; }; then
        echo "Error: API_SERVICE_URL needs USERNAME/PASSWORD or API_TOKEN"
        exit 1
    fi
    CMD_ARGS="$CMD_ARGS --api-service-url $API_SERVICE_URL"
    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        echo "Using username/password authentication (user: $USERNAME)"
        CMD_ARGS="$CMD_ARGS --username $USERNAME --password $PASSWORD"
    else
        echo "Using API token authentication"
        CMD_ARGS="$CMD_ARGS --api-token $API_TOKEN"
    fi
fi

exec python client_agent.py $CMD_ARGS
