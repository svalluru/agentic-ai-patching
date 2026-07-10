#!/usr/bin/env bash
# Build the console + RAG ingest image (cve_console, cve_flow, sample CSV).
set -euo pipefail

BUNDLE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"

oc project "${NAMESPACE}" 2>/dev/null || oc new-project "${NAMESPACE}"

if ! oc get bc agentic-patching-console -n "${NAMESPACE}" >/dev/null 2>&1; then
  oc apply -k "$(dirname "${BASH_SOURCE[0]}")/../cve-console" -n "${NAMESPACE}"
fi

echo "Build context: ${BUNDLE_ROOT} (app sources in local/)"
oc start-build agentic-patching-console --from-dir="${BUNDLE_ROOT}" --follow -n "${NAMESPACE}"

echo ""
echo "Image: image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/agentic-patching-console:latest"
echo "Used by: deployment/cve-console, jobs/rag-ingest, jobs/rag-reindex"
echo "Deploy stack: ./openshift/scripts/deploy.sh"
echo "Update console: oc apply -k openshift/cve-console -n ${NAMESPACE}"
