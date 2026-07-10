#!/usr/bin/env bash
# Update ingest scripts ConfigMap and re-run RAG ingest (resume-safe).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"

echo "Updating rag-ingest-scripts ConfigMap in ${NAMESPACE}..."
oc apply -k "${ROOT}/jobs/" -n "${NAMESPACE}"

echo "Deleting previous ingest job (required — Job spec is immutable)..."
oc delete job rag-ingest -n "${NAMESPACE}" --ignore-not-found --wait=true

echo "Starting rag-ingest (auto-resumes store named cve-host-history if present)..."
oc apply -f "${ROOT}/jobs/rag-ingest-job.yaml" -n "${NAMESPACE}"

echo ""
echo "Watch: oc logs -f job/rag-ingest -n ${NAMESPACE}"
echo "When complete, copy VECTOR_STORE_ID from logs into openshift/cve-console/configmap.yaml (VECTOR_DB_ID)"
