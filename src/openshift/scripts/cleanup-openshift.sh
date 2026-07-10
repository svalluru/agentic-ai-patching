#!/usr/bin/env bash
# Remove the Agentic Patching Console stack from an OpenShift cluster only.
# Does not touch local files, Docker, or remote AAP.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${NAMESPACE:-agentic-patching}"
KEEP_NAMESPACE=false
KEEP_IMAGE=false
DRY_RUN=false
ASSUME_YES=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Remove agentic-patching workloads from the current OpenShift cluster.

Options:
  -n, --namespace NAME   Namespace (default: agentic-patching)
  --keep-namespace       Delete workloads but leave the namespace
  --keep-image           Keep ImageStream/BuildConfig (agentic-patching-console)
  -y, --yes              Skip confirmation prompt
  --dry-run              Print actions only
  -h, --help             Show this help

Environment:
  NAMESPACE              Same as --namespace

Examples:
  ./openshift/scripts/cleanup-openshift.sh
  ./openshift/scripts/cleanup-openshift.sh -y --keep-image
  NAMESPACE=agentic-patching ./openshift/scripts/cleanup-openshift.sh --dry-run

Note: Vector stores in Llama Stack / Milvus are removed with the stack.
      Remote Ansible AAP is unchanged.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    --keep-namespace) KEEP_NAMESPACE=true; shift ;;
    --keep-image) KEEP_IMAGE=true; shift ;;
    -y|--yes) ASSUME_YES=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

run() {
  if [[ "${DRY_RUN}" == true ]]; then
    echo "[dry-run] $*"
  else
    echo "+ $*"
    "$@"
  fi
}

wait_for_absent() {
  local kind="$1" name="$2" timeout="${3:-120}"
  if [[ "${DRY_RUN}" == true ]]; then
    echo "[dry-run] wait for ${kind}/${name} to disappear (timeout ${timeout}s)"
    return 0
  fi
  local end=$((SECONDS + timeout))
  while (( SECONDS < end )); do
    if ! oc get "${kind}" "${name}" -n "${NAMESPACE}" &>/dev/null; then
      return 0
    fi
    sleep 3
  done
  echo "Warning: ${kind}/${name} still present after ${timeout}s" >&2
  return 0
}

if ! command -v oc &>/dev/null; then
  echo "Error: oc not found in PATH" >&2
  exit 1
fi

if ! oc whoami &>/dev/null; then
  echo "Error: not logged in to OpenShift (run oc login)" >&2
  exit 1
fi

CLUSTER="$(oc config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo unknown)"
CONTEXT="$(oc config current-context 2>/dev/null || echo unknown)"

if ! oc get namespace "${NAMESPACE}" &>/dev/null; then
  echo "Namespace ${NAMESPACE} does not exist on ${CLUSTER} — nothing to clean up."
  exit 0
fi

echo "OpenShift cleanup (cluster only)"
echo "  context:   ${CONTEXT}"
echo "  cluster:   ${CLUSTER}"
echo "  namespace: ${NAMESPACE}"
echo "  options:   keep-namespace=${KEEP_NAMESPACE} keep-image=${KEEP_IMAGE}"
echo ""

if [[ "${ASSUME_YES}" != true && "${DRY_RUN}" != true ]]; then
  read -r -p "Delete agentic-patching resources in this namespace? [y/N] " reply
  case "${reply}" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

echo ""
echo "=== Batch jobs ==="
run oc delete job rag-ingest rag-reindex -n "${NAMESPACE}" --ignore-not-found --wait=true

echo ""
echo "=== CVE console ==="
if [[ "${KEEP_IMAGE}" == true ]]; then
  run oc delete deployment,service,route,pvc,configmap/cve-console-config,configmap/cve-console-entrypoint \
    -l app.kubernetes.io/part-of=agentic-patching-console -n "${NAMESPACE}" --ignore-not-found --wait=true
  run oc delete deployment cve-console -n "${NAMESPACE}" --ignore-not-found --wait=true
  run oc delete service cve-console -n "${NAMESPACE}" --ignore-not-found
  run oc delete route cve-console -n "${NAMESPACE}" --ignore-not-found
  run oc delete pvc cve-console-data -n "${NAMESPACE}" --ignore-not-found --wait=true
  run oc delete configmap cve-console-config cve-console-entrypoint -n "${NAMESPACE}" --ignore-not-found
else
  run oc delete -k "${ROOT}/cve-console/" -n "${NAMESPACE}" --ignore-not-found --wait=true
fi

echo ""
echo "=== RAG ingest scripts ==="
run oc delete configmap rag-ingest-scripts -n "${NAMESPACE}" --ignore-not-found

echo ""
echo "=== Llama Stack distribution ==="
if oc get llamastackdistribution agentic-patching-llsd -n "${NAMESPACE}" &>/dev/null; then
  run oc delete llamastackdistribution agentic-patching-llsd -n "${NAMESPACE}" --wait=true --timeout=600s || true
  wait_for_absent llamastackdistribution agentic-patching-llsd 120
else
  echo "  (agentic-patching-llsd not found)"
fi

echo ""
echo "=== Llama Stack support (postgres, configmaps, PVCs) ==="
run oc delete -k "${ROOT}/llamastack/" -n "${NAMESPACE}" --ignore-not-found --wait=true

echo ""
echo "=== MCP servers ==="
run oc delete -k "${ROOT}/mcp/" -n "${NAMESPACE}" --ignore-not-found --wait=true
run oc delete deployment,service ansible-mcp -n "${NAMESPACE}" --ignore-not-found --wait=true

echo ""
echo "=== Milvus + etcd ==="
run oc delete -k "${ROOT}/milvus/" -n "${NAMESPACE}" --ignore-not-found --wait=true

echo ""
echo "=== Secrets ==="
run oc delete secret agentic-patching-app-secret llama-stack-inference-model-secret \
  llamastack-postgres-secret milvus-secret -n "${NAMESPACE}" --ignore-not-found

echo ""
echo "=== Leftover operator / LS pods ==="
if [[ "${DRY_RUN}" == true ]]; then
  echo "[dry-run] delete pods matching llama|llsd|milvus|insights-mcp in ${NAMESPACE}"
else
  leftover_pods="$(oc get pods -n "${NAMESPACE}" -o name 2>/dev/null \
    | grep -E 'llama|llsd|milvus|etcd|insights-mcp|cve-console|rag-' || true)"
  if [[ -n "${leftover_pods}" ]]; then
    echo "${leftover_pods}" | xargs oc delete -n "${NAMESPACE}" --ignore-not-found --wait=true 2>/dev/null || true
  fi
fi

if [[ "${KEEP_NAMESPACE}" == true ]]; then
  echo ""
  echo "=== Sweep remaining PVCs in namespace ==="
  run oc delete pvc --all -n "${NAMESPACE}" --ignore-not-found --wait=true

  echo ""
  echo "Done. Namespace ${NAMESPACE} kept (may be empty or hold unrelated resources)."
else
  echo ""
  echo "=== Namespace ==="
  run oc delete namespace "${NAMESPACE}" --wait=true --timeout=600s
  echo ""
  echo "Done. Namespace ${NAMESPACE} removed from ${CLUSTER}."
fi

echo ""
echo "Not removed (by design): remote AAP controller, GitHub repo, local bundle files."
