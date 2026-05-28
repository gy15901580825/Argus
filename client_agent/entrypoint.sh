#!/bin/bash
set -e

ORCHESTRATOR_URL=${ORCHESTRATOR_URL:-wss://www.example.com}
API_SERVICE_URL=${API_SERVICE_URL:-https://www.example.com}
AGENT_NAME=${AGENT_NAME:-default-client-agent}
USERNAME=${USERNAME:-}
PASSWORD=${PASSWORD:-}
API_TOKEN=${API_TOKEN:-}

if [ -z "$USERNAME" ] && [ -z "$PASSWORD" ] && [ -z "$API_TOKEN" ]; then
    echo "Error: Either username/password or API_TOKEN must be provided"
    exit 1
fi

CMD_ARGS="--orchestrator-url $ORCHESTRATOR_URL --api-service-url $API_SERVICE_URL --agent-name $AGENT_NAME"

if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
    echo "Using username/password authentication (user: $USERNAME)"
    CMD_ARGS="$CMD_ARGS --username $USERNAME --password $PASSWORD"
elif [ -n "$API_TOKEN" ]; then
    echo "Using API token authentication"
    CMD_ARGS="$CMD_ARGS --api-token $API_TOKEN"
fi

exec python client_agent.py $CMD_ARGS
