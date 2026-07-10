#!/bin/bash
# Apply Milvus OpenAI vector-store cache fix before uvicorn starts (llama-stack #5209).
set -euo pipefail
python3 /etc/llama-stack/patch-milvus-openai-cache.py
exec /opt/app-root/bin/python3.12 /opt/app-root/bin/uvicorn \
  llama_stack.core.server.server:create_app \
  --host 0.0.0.0 --port 8321 --workers 1 --factory
