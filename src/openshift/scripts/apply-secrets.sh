#!/usr/bin/env bash
# Create/update OpenShift secrets from openshift/.env.openshift (not committed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT}/.env.openshift}"
NAMESPACE="${NAMESPACE:-agentic-patching}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--env-file PATH] [-n NAMESPACE]

Apply secrets to the cluster from openshift/.env.openshift.

Copy and edit: cp openshift/.env.openshift.example openshift/.env.openshift
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Error: env file not found: ${ENV_FILE}" >&2
  echo "Copy openshift/.env.openshift.example → openshift/.env.openshift" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "${ENV_FILE}"
set +a

NAMESPACE="${NAMESPACE:-agentic-patching}"

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Error: required variable ${name} is empty in ${ENV_FILE}" >&2
    exit 1
  fi
}

require_var AAP_BASE_URL
require_var AAP_TOKEN
require_var GIT_HUB_TOKEN
require_var LIGHTSPEED_CLIENT_ID
require_var LIGHTSPEED_CLIENT_SECRET
require_var VLLM_URL
require_var VLLM_API_TOKEN

postgres_password="${POSTGRES_PASSWORD:-changeme}"
milvus_password="${MILVUS_ROOT_PASSWORD:-changeme}"

echo "Applying secrets to namespace ${NAMESPACE} from ${ENV_FILE}..."

oc create secret generic agentic-patching-app-secret -n "${NAMESPACE}" \
  --from-literal=LIGHTSPEED_CLIENT_ID="${LIGHTSPEED_CLIENT_ID}" \
  --from-literal=LIGHTSPEED_CLIENT_SECRET="${LIGHTSPEED_CLIENT_SECRET}" \
  --from-literal=GIT_HUB_TOKEN="${GIT_HUB_TOKEN}" \
  --from-literal=AAP_TOKEN="${AAP_TOKEN}" \
  --from-literal=AAP_BASE_URL="${AAP_BASE_URL}" \
  --dry-run=client -o yaml | oc apply -f -

oc create secret generic llama-stack-inference-model-secret -n "${NAMESPACE}" \
  --from-literal=INFERENCE_MODEL="${INFERENCE_MODEL:-llama-17b/llama-scout-17b}" \
  --from-literal=VLLM_URL="${VLLM_URL}" \
  --from-literal=VLLM_TLS_VERIFY="${VLLM_TLS_VERIFY:-false}" \
  --from-literal=VLLM_API_TOKEN="${VLLM_API_TOKEN}" \
  --dry-run=client -o yaml | oc apply -f -

oc create secret generic llamastack-postgres-secret -n "${NAMESPACE}" \
  --from-literal=password="${postgres_password}" \
  --dry-run=client -o yaml | oc apply -f -

oc create secret generic milvus-secret -n "${NAMESPACE}" \
  --from-literal=root-password="${milvus_password}" \
  --from-literal=MILVUS_ENDPOINT="tcp://milvus-service:19530" \
  --from-literal=MILVUS_TOKEN="" \
  --from-literal=MILVUS_CONSISTENCY_LEVEL="Bounded" \
  --dry-run=client -o yaml | oc apply -f -

echo "Done."
