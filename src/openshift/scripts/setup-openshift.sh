#!/usr/bin/env bash
# End-to-end Agentic Patching Console setup on OpenShift / RHOAI.
# Secrets come from openshift/.env.openshift (not committed to git).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT}/.env.openshift}"
NAMESPACE="${NAMESPACE:-agentic-patching}"
SKIP_RAG_INGEST="${SKIP_RAG_INGEST:-false}"
SKIP_BUILD="${SKIP_BUILD:-false}"
SKIP_AAP_VERIFY="${SKIP_AAP_VERIFY:-false}"
ASSUME_YES=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Full cluster setup: secrets → infra → image → console → RAG → VECTOR_DB_ID → route.

Options:
  --env-file PATH     Env file (default: openshift/.env.openshift)
  -n, --namespace NS  Override NAMESPACE from env file
  --skip-rag          Skip RAG ingest (infra + console only)
  --skip-build        Skip console image build
  --skip-aap-verify   Skip AAP ping from console pod
  -y, --yes           Skip confirmation prompt
  -h, --help          Show this help

Quick start:
  cp openshift/.env.openshift.example openshift/.env.openshift
  # edit openshift/.env.openshift
  ./openshift/scripts/setup-openshift.sh

See openshift/OPENSHIFT-DEPLOY.md for prerequisites.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file) ENV_FILE="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    --skip-rag) SKIP_RAG_INGEST=true; shift ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    --skip-aap-verify) SKIP_AAP_VERIFY=true; shift ;;
    -y|--yes) ASSUME_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null || { echo "Error: $1 not found in PATH" >&2; exit 1; }
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Error: required variable ${name} is empty (set in ${ENV_FILE})" >&2
    exit 1
  fi
}

detect_llama_stack_url() {
  local svc=""
  svc="$(oc get svc -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null \
    | grep -E 'llsd.*service|llama-stack|llsd' | grep -v postgres | head -1 || true)"
  if [[ -z "${svc}" ]]; then
    svc="agentic-patching-llsd-service"
  fi
  echo "http://${svc}:8321"
}

apply_secrets_from_env() {
  ENV_FILE="${ENV_FILE}" NAMESPACE="${NAMESPACE}" "${SCRIPT_DIR}/apply-secrets.sh"
}

patch_console_config() {
  local vector_db_id="${1:-}"
  oc apply -k "${ROOT}/cve-console/" -n "${NAMESPACE}"
  oc patch configmap cve-console-config -n "${NAMESPACE}" --type merge -p "$(cat <<EOF
{
  "data": {
    "AAP_DEFAULT_PROJECT_ID": "${AAP_DEFAULT_PROJECT_ID}",
    "AAP_DEFAULT_INVENTORY_ID": "${AAP_DEFAULT_INVENTORY_ID}",
    "AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID": "${AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID}",
    "AAP_DEFAULT_ORGANIZATION_ID": "${AAP_DEFAULT_ORGANIZATION_ID}",
    "AAP_VERIFY_TLS": "${AAP_VERIFY_TLS:-false}",
    "VECTOR_DB_ID": "${vector_db_id}"
  }
}
EOF
)"
}

patch_llama_endpoint() {
  local url="$1"
  oc patch configmap agentic-patching-llamastack-endpoint -n "${NAMESPACE}" \
    --type merge -p "{\"data\":{\"LLAMA_STACK_URL\":\"${url}\"}}" 2>/dev/null \
    || oc apply -f "${ROOT}/llamastack/service-endpoint-configmap.yaml" -n "${NAMESPACE}"
  oc patch configmap agentic-patching-llamastack-endpoint -n "${NAMESPACE}" \
    --type merge -p "{\"data\":{\"LLAMA_STACK_URL\":\"${url}\"}}"
}

run_rag_ingest() {
  local log_file vector_db_id log_pid progress_pid

  echo "Updating ingest scripts and starting rag-ingest job..." >&2
  oc apply -k "${ROOT}/jobs/" -n "${NAMESPACE}" >&2
  oc delete job rag-ingest -n "${NAMESPACE}" --ignore-not-found --wait=true >&2
  oc apply -f "${ROOT}/jobs/rag-ingest-job.yaml" -n "${NAMESPACE}" >&2

  echo "Waiting for rag-ingest pod..." >&2
  local deadline=$((SECONDS + 300))
  while (( SECONDS < deadline )); do
    if oc get pods -n "${NAMESPACE}" -l job-name=rag-ingest -o name 2>/dev/null | grep -q .; then
      break
    fi
    sleep 3
  done
  oc wait --for=condition=Ready pod -l job-name=rag-ingest -n "${NAMESPACE}" --timeout=300s >&2 || true

  log_file="$(mktemp)"
  echo "Following rag-ingest logs (may take 30–120 minutes)..." >&2
  echo "Watch for: Rows to ingest, Uploading rows N..M, Checkpoint completed=X/total" >&2
  echo "" >&2

  # Stream to stderr + log file. stdout is reserved for VECTOR_STORE_ID return value.
  oc logs -f job/rag-ingest -n "${NAMESPACE}" 2>&1 | tee "${log_file}" >&2 &
  log_pid=$!

  (
    last_summary=""
    while kill -0 "${log_pid}" 2>/dev/null; do
      if [[ -f "${log_file}" ]]; then
        total="$(grep -E '^Rows to ingest:' "${log_file}" | tail -1 | sed 's/^Rows to ingest: //' || true)"
        resume="$(grep -E '^Resume:' "${log_file}" | tail -1 || true)"
        checkpoint="$(grep -E '^Checkpoint: store completed=' "${log_file}" | tail -1 || true)"
        uploading="$(grep -E '^Uploading rows ' "${log_file}" | tail -1 || true)"
        summary=""
        [[ -n "${total}" ]] && summary="total_rows=${total}"
        [[ -n "${resume}" ]] && summary="${summary:+$summary | }${resume}"
        [[ -n "${uploading}" ]] && summary="${summary:+$summary | }${uploading}"
        [[ -n "${checkpoint}" ]] && summary="${summary:+$summary | }${checkpoint}"
        if [[ -n "${summary}" && "${summary}" != "${last_summary}" ]]; then
          echo "[rag-ingest] ${summary}" >&2
          last_summary="${summary}"
        fi
      fi
      sleep 30
    done
  ) &
  progress_pid=$!

  if ! oc wait --for=condition=complete job/rag-ingest -n "${NAMESPACE}" --timeout=7200s >&2; then
    kill "${log_pid}" "${progress_pid}" 2>/dev/null || true
    wait "${log_pid}" 2>/dev/null || true
    wait "${progress_pid}" 2>/dev/null || true
    echo "" >&2
    echo "RAG ingest did not complete. Resume with:" >&2
    echo "  ./openshift/scripts/rerun-rag-ingest.sh" >&2
    rm -f "${log_file}"
    exit 1
  fi

  kill "${log_pid}" "${progress_pid}" 2>/dev/null || true
  wait "${log_pid}" 2>/dev/null || true
  wait "${progress_pid}" 2>/dev/null || true

  vector_db_id="$(grep -Eo 'VECTOR_STORE_ID=vs_[a-f0-9-]+' "${log_file}" | tail -1 | cut -d= -f2- || true)"
  if [[ -z "${vector_db_id}" ]]; then
    vector_db_id="$(grep -Eo 'vs_[a-f0-9-]{36}' "${log_file}" | tail -1 || true)"
  fi

  final_line="$(grep -E '^Completed files:' "${log_file}" | tail -1 || true)"
  if [[ -n "${final_line}" ]]; then
    echo "" >&2
    echo "RAG ingest finished: ${final_line}" >&2
  fi
  if grep -q 'Result: ALL ROWS INDEXED' "${log_file}" 2>/dev/null; then
    echo "RAG ingest: ALL ROWS INDEXED" >&2
  elif grep -q 'Result: PARTIAL' "${log_file}" 2>/dev/null; then
    echo "RAG ingest: PARTIAL — rerun ./openshift/scripts/rerun-rag-ingest.sh" >&2
  fi

  rm -f "${log_file}"

  if [[ -z "${vector_db_id}" ]]; then
    echo "Error: could not parse VECTOR_STORE_ID from rag-ingest logs" >&2
    exit 1
  fi

  RAG_VECTOR_STORE_ID="${vector_db_id}"
}

verify_aap_from_pod() {
  echo "Verifying remote AAP from cve-console pod..."
  oc exec deploy/cve-console -n "${NAMESPACE}" -- python3 - <<'PY'
import json, os, ssl, urllib.error, urllib.request

base = os.environ["AAP_BASE_URL"].split("/api/controller/")[0].rstrip("/")
tok = os.environ["AAP_TOKEN"]
verify = os.environ.get("AAP_VERIFY_TLS", "true").lower() not in ("0", "false", "no")
ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
url = f"{base}/api/controller/v2/ping/"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
try:
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        print(json.dumps(json.load(resp), indent=2))
except urllib.error.HTTPError as e:
    print(f"AAP ping HTTP {e.code}: {e.read().decode()}", flush=True)
    raise SystemExit(1)
except Exception as e:
    print(f"AAP ping failed: {e}", flush=True)
    raise SystemExit(1)
PY
}

# --- Preflight ---
require_cmd oc

if ! oc whoami >/dev/null 2>&1; then
  echo "Error: not logged in to OpenShift (run oc login)" >&2
  exit 1
fi

if ! oc get crd llamastackdistributions.llamastack.io >/dev/null 2>&1; then
  echo "Error: Llama Stack operator CRD not found (install RHOAI / Llama Stack operator)" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Error: env file not found: ${ENV_FILE}" >&2
  echo "Copy openshift/.env.openshift.example → openshift/.env.openshift and edit." >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "${ENV_FILE}"
set +a

NAMESPACE="${NAMESPACE:-agentic-patching}"
SKIP_RAG_INGEST="${SKIP_RAG_INGEST:-false}"
SKIP_BUILD="${SKIP_BUILD:-false}"

require_var AAP_BASE_URL
require_var AAP_TOKEN
require_var GIT_HUB_TOKEN
require_var LIGHTSPEED_CLIENT_ID
require_var LIGHTSPEED_CLIENT_SECRET
require_var VLLM_URL
require_var VLLM_API_TOKEN

CLUSTER="$(oc config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo unknown)"
CONTEXT="$(oc config current-context 2>/dev/null || echo unknown)"

echo "Agentic Patching Console — OpenShift setup"
echo "  context:   ${CONTEXT}"
echo "  cluster:   ${CLUSTER}"
echo "  namespace: ${NAMESPACE}"
echo "  env file:  ${ENV_FILE}"
echo "  skip rag:  ${SKIP_RAG_INGEST}  skip build: ${SKIP_BUILD}"
echo ""

if [[ "${ASSUME_YES}" != true ]]; then
  read -r -p "Proceed with setup on this cluster? [y/N] " reply
  case "${reply}" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

echo ""
echo "=== Namespace ==="
oc project "${NAMESPACE}" 2>/dev/null || oc new-project "${NAMESPACE}"

echo ""
echo "=== Secrets ==="
apply_secrets_from_env

echo ""
echo "=== Infrastructure (Milvus, MCP, Llama Stack) ==="
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

echo ""
echo "=== Llama Stack URL ==="
if [[ -z "${LLAMA_STACK_URL:-}" ]]; then
  LLAMA_STACK_URL="$(detect_llama_stack_url)"
fi
patch_llama_endpoint "${LLAMA_STACK_URL}"
echo "LLAMA_STACK_URL=${LLAMA_STACK_URL}"

echo ""
echo "=== Console config ==="
patch_console_config ""

echo ""
if [[ "${SKIP_BUILD}" != true ]]; then
  echo "=== Build console image ==="
  "${SCRIPT_DIR}/build-console-image.sh"
else
  echo "=== Build skipped (--skip-build) ==="
fi

echo ""
echo "=== Deploy / wait for cve-console ==="
oc rollout status deployment/cve-console -n "${NAMESPACE}" --timeout=300s

VECTOR_DB_ID=""
if [[ "${SKIP_RAG_INGEST}" == true ]]; then
  echo ""
  echo "=== RAG ingest skipped (--skip-rag) ==="
  echo "Run later: ./openshift/scripts/rerun-rag-ingest.sh"
else
  echo ""
  echo "=== RAG ingest ==="
  RAG_VECTOR_STORE_ID=""
  run_rag_ingest
  VECTOR_DB_ID="${RAG_VECTOR_STORE_ID}"
  echo "Parsed VECTOR_DB_ID=${VECTOR_DB_ID}"

  echo ""
  echo "=== Wire VECTOR_DB_ID into console ==="
  patch_console_config "${VECTOR_DB_ID}"
  oc rollout restart deployment/cve-console -n "${NAMESPACE}"
  oc rollout status deployment/cve-console -n "${NAMESPACE}" --timeout=300s
fi

if [[ "${SKIP_AAP_VERIFY}" != true ]]; then
  echo ""
  verify_aap_from_pod || echo "Warning: AAP ping failed (check network / token / AAP_VERIFY_TLS)"
fi

ROUTE_URL="$(oc get route cve-console -n "${NAMESPACE}" -o jsonpath='https://{.spec.host}' 2>/dev/null || true)"

echo ""
echo "=== Setup complete ==="
if [[ -n "${ROUTE_URL}" ]]; then
  echo "Console: ${ROUTE_URL}"
else
  echo "Console route not found — check: oc get route -n ${NAMESPACE}"
fi
if [[ -n "${VECTOR_DB_ID}" ]]; then
  echo "VECTOR_DB_ID: ${VECTOR_DB_ID}"
fi
echo "Logs: oc logs -f deploy/cve-console -n ${NAMESPACE}"
