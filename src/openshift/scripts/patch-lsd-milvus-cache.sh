#!/usr/bin/env bash
# Apply Milvus OpenAI vector-store cache fix inside the operator-managed LSD pod.
# Fixes: "Vector Store 'vs_...' not found" on search after LSD restart (llama-stack #5209).
#
# Usage (from Mac/bastion with oc in PATH):
#   ./openshift/scripts/patch-lsd-milvus-cache.sh
#   ./openshift/scripts/patch-lsd-milvus-cache.sh --restart
set -euo pipefail

NAMESPACE="${NAMESPACE:-agentic-patching}"
RESTART=false
for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=true ;;
  esac
done

OC="${OC:-oc}"
if ! command -v "$OC" >/dev/null 2>&1 && [[ -x /usr/local/bin/oc ]]; then
  OC=/usr/local/bin/oc
fi

POD="$("$OC" get pods -l app=llama-stack -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}')"
echo "LSD pod: $POD"

"$OC" cp "$(dirname "$0")/../../local/scripts/patch-milvus-openai-cache.py" \
  "$NAMESPACE/$POD:/tmp/patch-milvus-openai-cache.py"

"$OC" exec -n "$NAMESPACE" "$POD" -- python3 /tmp/patch-milvus-openai-cache.py

if [[ "$RESTART" == true ]]; then
  echo "Restarting LSD pod..."
  "$OC" delete pod -n "$NAMESPACE" "$POD" --wait=true
  "$OC" wait --for=condition=Ready pod -l app=llama-stack -n "$NAMESPACE" --timeout=300s
  echo "Re-applying patch after restart (operator image is ephemeral)..."
  POD="$("$OC" get pods -l app=llama-stack -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}')"
  "$OC" cp "$(dirname "$0")/../../local/scripts/patch-milvus-openai-cache.py" \
    "$NAMESPACE/$POD:/tmp/patch-milvus-openai-cache.py"
  "$OC" exec -n "$NAMESPACE" "$POD" -- python3 /tmp/patch-milvus-openai-cache.py
  echo "Patch applied. Send SIGHUP or restart llama-stack process if search still fails."
fi

echo "Done. Test search from a cluster pod:"
echo '  curl -s -X POST "$LLAMA_STACK_URL/v1/vector_stores/<VS_ID>/search" -H "Content-Type: application/json" -d '"'"'{"query":"bastion","max_num_results":3}'"'"
