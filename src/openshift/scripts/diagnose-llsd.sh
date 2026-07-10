#!/usr/bin/env bash
# Diagnose LlamaStackDistribution / Llama Stack pod issues on OpenShift.
set -euo pipefail

NAMESPACE="${NAMESPACE:-agentic-patching}"
CR_NAME="${CR_NAME:-agentic-patching-llsd}"

echo "=== Namespace: ${NAMESPACE} ==="
oc get ns "${NAMESPACE}" 2>/dev/null || { echo "Namespace not found"; exit 1; }

echo ""
echo "=== Llama Stack Operator (cluster) ==="
oc get csv -A 2>/dev/null | grep -i llama || true
oc get pods -A 2>/dev/null | grep -i 'llama-stack.*operator' || true

echo ""
echo "=== LlamaStackDistribution CR ==="
if oc get llamastackdistribution "${CR_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  oc get llamastackdistribution "${CR_NAME}" -n "${NAMESPACE}" -o wide
  echo ""
  oc get llamastackdistribution "${CR_NAME}" -n "${NAMESPACE}" -o jsonpath='Phase: {.status.phase}{"\n"}Message: {.status.message}{"\n"}' 2>/dev/null || true
  echo ""
  echo "--- describe (events at bottom) ---"
  oc describe llamastackdistribution "${CR_NAME}" -n "${NAMESPACE}" | tail -40
else
  echo "NOT FOUND: llamastackdistribution/${CR_NAME}"
  echo "Apply with: oc apply -k openshift/"
fi

echo ""
echo "=== PostgreSQL (required for RHOAI 3.2+) ==="
oc get deploy,svc,pvc llamastack-postgres -n "${NAMESPACE}" 2>/dev/null || echo "llamastack-postgres not deployed"

echo ""
echo "=== All llama / llsd resources in namespace ==="
oc get deploy,sts,rs,pod,svc -n "${NAMESPACE}" 2>/dev/null | grep -iE 'llama|llsd|postgres' || echo "(none matching llama|llsd|postgres)"

echo ""
echo "=== Pods by label app=llama-stack ==="
oc get pods -l app=llama-stack -n "${NAMESPACE}" 2>/dev/null || true

echo ""
echo "=== Pods matching CR name prefix ==="
oc get pods -n "${NAMESPACE}" 2>/dev/null | grep -E "${CR_NAME}|llama" || echo "(none)"

echo ""
echo "=== Recent namespace events ==="
oc get events -n "${NAMESPACE}" --sort-by='.lastTimestamp' 2>/dev/null | tail -15

echo ""
echo "=== ConfigMap (userConfig) ==="
oc get configmap agentic-patching-llamastack-config -n "${NAMESPACE}" -o jsonpath='keys: {.data}' 2>/dev/null | head -c 200 || echo "configmap not found"
echo ""

POD="$(oc get pods -n "${NAMESPACE}" -o name 2>/dev/null | grep -E 'llama|llsd' | head -1 || true)"
if [[ -n "${POD}" ]]; then
  echo ""
  echo "=== Logs from ${POD} (last 40 lines) ==="
  oc logs "${POD}" -n "${NAMESPACE}" --tail=40 2>/dev/null || oc logs "${POD}" -n "${NAMESPACE}" --previous --tail=40 2>/dev/null || true
fi
