#!/bin/bash

# curl -s -X POST http://localhost:8000/tasks \
#   -H 'Content-Type: application/json' \
#   -d '{"url": "https://example-target.com/", "max_steps": 50, "headless": false, "llm_model": "gpt-5.3-codex"}'



docker run -itd -e DISPLAY=$DISPLAY --network host -v /tmp/.X11-unix:/tmp/.X11-unix --shm-size=2g -v /home/ygao/Workspace/Github/argus:/app claude-dev-env /bin/bash