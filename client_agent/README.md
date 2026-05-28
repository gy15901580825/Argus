# client_agent

docker pull <your-gh-user>/client_agent:latest

docker run -e ORCHESTRATOR_URL=wss://api.example.com \
           -e API_SERVICE_URL=https://api.example.com \
           -e AGENT_NAME=my-agent \
           -e USERNAME=ygao \
           -e PASSWORD=Test@123456 \
           <your-gh-user>/client_agent:latest

python client_agent.py --orchestrator-url wss://api.example.com --api-service-url https://api.example.com --agent-name my-agent --username ygao --password Test@123456