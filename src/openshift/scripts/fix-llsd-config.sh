#!/usr/bin/env bash
# Apply Llama Stack config from this bundle and verify the cluster ConfigMap has no stale APIs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"
CM_NAME="agentic-patching-llamastack-config"

echo "Applying llamastack kustomize from: ${ROOT}/llamastack"
oc apply -k "${ROOT}/llamastack/"

echo ""
echo "=== ConfigMap apis: (cluster) ==="
if ! oc get configmap "${CM_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  echo "ERROR: ConfigMap ${CM_NAME} not found in ${NAMESPACE}"
  exit 1
fi

APIS="$(oc get configmap "${CM_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data.config\.yaml}' | rg '^apis:' -A10 || true)"
echo "${APIS}"

if echo "${APIS}" | rg -q '^\s+- messages'; then
  echo ""
  echo "ERROR: ConfigMap still contains 'messages' API."
  echo "You are likely applying from an OLD bundle copy. Re-run from:"
  echo "  ${ROOT}/../.."
  echo "Or force replace:"
  echo "  oc create configmap ${CM_NAME} --from-file=config.yaml=${ROOT}/llamastack/run.yaml -n ${NAMESPACE} --dry-run=client -o yaml | oc replace -f -"
  exit 1
fi

TOOL_RUNTIME="$(oc get configmap "${CM_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data.config\.yaml}' | rg 'tool_runtime:' -A8 || true)"
if echo "${TOOL_RUNTIME}" | rg -q 'inline::rag-runtime'; then
  echo ""
  echo "ERROR: ConfigMap still uses inline::rag-runtime (not in RHOAI 0.7.1)."
  echo "Expected: inline::file-search. Force replace config from ${ROOT}/llamastack/run.yaml"
  exit 1
fi

if ! oc get configmap "${CM_NAME}" -n "${NAMESPACE}" -o jsonpath='{.data.config\.yaml}' | rg -q '^  - files'; then
  echo ""
  echo "ERROR: ConfigMap missing 'files' API (required by inline::file-search)."
  echo "Force replace config from ${ROOT}/llamastack/run.yaml"
  exit 1
fi

echo ""
echo "Restarting Llama Stack pod..."
oc delete pod -l app=llama-stack -n "${NAMESPACE}" --ignore-not-found
POD="$(oc get pods -n "${NAMESPACE}" -o name 2>/dev/null | grep -E 'llsd|llama-stack' | head -1 || true)"
if [[ -n "${POD}" ]]; then
  oc delete "${POD}" -n "${NAMESPACE}" --ignore-not-found
fi

echo "Wait for Ready:"
echo "  oc wait --for=jsonpath='{.status.phase}'=Ready llamastackdistribution/agentic-patching-llsd -n ${NAMESPACE} --timeout=600s"
echo "  oc logs -l app=llama-stack -n ${NAMESPACE} --tail=30"
