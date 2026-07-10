#!/bin/bash
# Re-index files already uploaded to an existing vector store (no CSV re-upload).
# Run AFTER ./openshift/scripts/patch-lsd-milvus-cache.sh on the LSD pod.
set -euo pipefail

LLAMA_URL="${LLAMA_STACK_URL:?Set LLAMA_STACK_URL}"
SOURCE_STORE_ID="${SOURCE_STORE_ID:?Set SOURCE_STORE_ID (existing store with completed files)}"
STORE_NAME="${STORE_NAME:-cve-host-history-reindex}"
BATCH_SIZE="${BATCH_SIZE:-100}"

ARGS=(
  --endpoint "${LLAMA_URL}"
  --source-store-id "${SOURCE_STORE_ID}"
  --store-name "${STORE_NAME}"
  --batch-size "${BATCH_SIZE}"
)
if [[ -n "${TARGET_STORE_ID:-}" ]]; then
  ARGS+=(--target-store-id "${TARGET_STORE_ID}")
fi

echo "Re-indexing from ${SOURCE_STORE_ID} (reuse uploaded files, no CSV upload)"
python3 /scripts/reindex-from-store.py "${ARGS[@]}"
