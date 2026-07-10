#!/usr/bin/env bash
# Deploy Agentic Patching Console stack to OpenShift / RHOAI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"

echo "Deploying infrastructure to namespace: ${NAMESPACE}"

ENV_FILE="${ROOT}/.env.openshift"
if [[ -f "${ENV_FILE}" ]]; then
  echo "Applying secrets from ${ENV_FILE}..."
  ENV_FILE="${ENV_FILE}" NAMESPACE="${NAMESPACE}" "${SCRIPT_DIR}/apply-secrets.sh"
else
  echo "Warning: ${ENV_FILE} not found — run apply-secrets.sh or setup-openshift.sh first" >&2
fi

oc apply -k "${ROOT}"

echo ""
echo "Waiting for Milvus..."
oc rollout status deployment/milvus-standalone -n "${NAMESPACE}" --timeout=300s

echo ""
echo "Waiting for Insights MCP..."
oc rollout status deployment/insights-mcp -n "${NAMESPACE}" --timeout=180s

echo ""
echo "Waiting for PostgreSQL (Llama Stack metadata)..."
oc rollout status deployment/llamastack-postgres -n "${NAMESPACE}" --timeout=300s

echo ""
echo "Waiting for LlamaStackDistribution..."
oc wait --for=jsonpath='{.status.phase}'=Ready \
  llamastackdistribution/agentic-patching-llsd -n "${NAMESPACE}" --timeout=600s

LLAMA_SVC="$(oc get svc -n "${NAMESPACE}" -o name | grep -E 'llama|llsd' | head -1 || true)"
if [[ -n "${LLAMA_SVC}" ]]; then
  echo "Llama Stack service: ${LLAMA_SVC}"
fi

echo ""
echo "Building console image (required before cve-console pod / RAG jobs)..."
"${SCRIPT_DIR}/build-console-image.sh"

echo ""
echo "Deploying cve-console..."
oc apply -k "${ROOT}/cve-console" -n "${NAMESPACE}"
oc rollout status deployment/cve-console -n "${NAMESPACE}" --timeout=300s

echo ""
echo "Done. For full automation (RAG + VECTOR_DB_ID): ./openshift/scripts/setup-openshift.sh"
echo "Or manual next steps (see openshift/OPENSHIFT-DEPLOY.md):"
echo "  1. Confirm LLAMA_STACK_URL in openshift/llamastack/service-endpoint-configmap.yaml"
echo "  2. ./openshift/scripts/rerun-rag-ingest.sh"
echo "  3. Set VECTOR_DB_ID in openshift/cve-console/configmap.yaml → oc apply + rollout restart"
echo "  4. oc get route cve-console -n ${NAMESPACE}"
