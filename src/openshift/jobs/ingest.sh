#!/bin/bash
set -euo pipefail

LLAMA_URL="${LLAMA_STACK_URL:?Set LLAMA_STACK_URL via agentic-patching-llamastack-endpoint ConfigMap}"
CSV="${CSV_PATH:-/app/cve-sample-historical-1000.csv}"
STORE_NAME="${STORE_NAME:-cve-host-history}"
PROVIDER_ID="${VECTOR_PROVIDER_ID:-milvus-remote}"
CURL_OPTS="${CURL_OPTS:---http1.1 --connect-timeout 30 --max-time 600}"

echo "Llama Stack: ${LLAMA_URL}"
MODELS_JSON="$(curl ${CURL_OPTS} -sf "${LLAMA_URL}/v1/models")"
echo "Models: ${MODELS_JSON}"

read -r EMBEDDING_MODEL EMBEDDING_DIM <<<"$(EMBEDDING_MODEL="${EMBEDDING_MODEL:-}" MODELS_JSON="${MODELS_JSON}" python3 - <<'PY'
import json, os, sys

preferred = os.environ.get("EMBEDDING_MODEL") or ""
raw = json.loads(os.environ["MODELS_JSON"])
items = raw.get("data", raw if isinstance(raw, list) else [])

def model_id(item):
    return item.get("id") or item.get("identifier") or ""

def item_meta(item):
    return item.get("metadata") or item.get("custom_metadata") or {}

def is_embedding(item):
    mid = model_id(item)
    meta = item_meta(item)
    mtype = (item.get("model_type") or item.get("type") or meta.get("model_type") or "").lower()
    if mtype == "embedding":
        return True
    if meta.get("embedding_dimension"):
        return True
    return any(x in mid.lower() for x in ("embed", "nomic"))

chosen = None
if preferred:
    for item in items:
        if model_id(item) == preferred:
            chosen = item
            break
if chosen is None:
    for item in items:
        if is_embedding(item):
            chosen = item
            break

if chosen is None:
    print("ERROR: no embedding model in /v1/models; set EMBEDDING_MODEL or fix LSD config", file=sys.stderr)
    sys.exit(1)

mid = model_id(chosen)
meta = item_meta(chosen)
dim = meta.get("embedding_dimension") or 768
print(mid, int(dim))
PY
)"

echo "Using embedding model: ${EMBEDDING_MODEL} (dim=${EMBEDDING_DIM})"

lookup_store_by_name() {
  local json
  json="$(curl ${CURL_OPTS} -sf "${LLAMA_URL}/v1/vector_stores?limit=100")"
  STORE_NAME="${STORE_NAME}" STORES_JSON="${json}" python3 - <<'PY'
import json, os, sys
raw = json.loads(os.environ["STORES_JSON"])
items = raw.get("data", raw if isinstance(raw, list) else [])
name = os.environ.get("STORE_NAME", "")
matches = [i for i in items if (i.get("name") or "") == name and i.get("id")]
if not matches:
    sys.exit(1)
def completed(item):
    fc = item.get("file_counts") or {}
    return int(fc.get("completed", 0) or 0)
best = max(matches, key=completed)
print(best["id"])
PY
}

if [[ -n "${VECTOR_STORE_ID:-}" ]]; then
  echo "Using vector store from VECTOR_STORE_ID: ${VECTOR_STORE_ID}"
elif VECTOR_STORE_ID="$(lookup_store_by_name 2>/dev/null || true)" && [[ -n "${VECTOR_STORE_ID}" ]]; then
  echo "Resuming existing vector store named '${STORE_NAME}': ${VECTOR_STORE_ID}"
else
  echo "Creating vector store ${STORE_NAME} (provider=${PROVIDER_ID})..."
  CREATE_PAYLOAD="$(STORE_NAME="${STORE_NAME}" PROVIDER_ID="${PROVIDER_ID}" \
    EMBEDDING_MODEL="${EMBEDDING_MODEL}" EMBEDDING_DIM="${EMBEDDING_DIM}" \
    python3 - <<'PY'
import json, os
print(json.dumps({
    "name": os.environ["STORE_NAME"],
    "provider_id": os.environ["PROVIDER_ID"],
    "embedding_model": os.environ["EMBEDDING_MODEL"],
    "embedding_dimension": int(os.environ["EMBEDDING_DIM"]),
}))
PY
)"
  CREATE_RESP="$(curl ${CURL_OPTS} -sS -X POST "${LLAMA_URL}/v1/vector_stores" \
    -H 'Content-Type: application/json' \
    -d "${CREATE_PAYLOAD}")"
  echo "Create response: ${CREATE_RESP}"
  if echo "${CREATE_RESP}" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if "id" in d else 1)'; then
    VECTOR_STORE_ID="$(printf '%s' "${CREATE_RESP}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  else
    echo "ERROR: vector store create failed: ${CREATE_RESP}" >&2
    exit 1
  fi
  echo "Vector store ID: ${VECTOR_STORE_ID}"
fi

echo ""
echo ">>> VECTOR_STORE_ID=${VECTOR_STORE_ID}  (save this — set VECTOR_DB_ID in cve-console-config)"
echo ""

python3 /scripts/gpt-ingest-rhoai.py "${CSV}" \
  --endpoint "${LLAMA_URL}" \
  --resume-store-id "${VECTOR_STORE_ID}" \
  --batch-size "${BATCH_SIZE:-5}" \
  --wait-seconds "${WAIT_SECONDS:-180}"

echo ""
echo "Ingestion complete."
echo "Set VECTOR_DB_ID in cve-console-config:"
echo "  VECTOR_DB_ID: \"${VECTOR_STORE_ID}\""
