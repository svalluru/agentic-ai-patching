#!/usr/bin/env bash
# Create/update AAP project + GitHub SCM credential and sync (no AAP UI).
# Usage (from src/):
#   ./openshift/scripts/setup-aap-project.sh
#   ./openshift/scripts/setup-aap-project.sh --project-id 6
#   ./openshift/scripts/setup-aap-project.sh --sync-only --project-id 6
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT}/.env.openshift}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--env-file PATH] [setup-aap-project.py args...]

Loads openshift/.env.openshift (AAP_*, GIT_HUB_TOKEN, optional GITHUB_REPO_*),
then creates/updates:
  - Source Control credential (GitHub PAT)
  - AAP Project (git → playbook repo)
  - Project sync + playbook list

Requires: AAP_BASE_URL, AAP_TOKEN, GIT_HUB_TOKEN, AAP_PROJECT_NAME
Optional: AAP_DEFAULT_ORGANIZATION_ID, GITHUB_REPO_OWNER/NAME/BRANCH

After success, writes AAP_DEFAULT_PROJECT_ID into the env file and patches
cve-console-config (unless --skip-env-update / --skip-console-patch).
EOF
}

EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      ENV_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      EXTRA+=("$1")
      shift
      ;;
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

exec python3 "${SCRIPT_DIR}/setup-aap-project.py" --env-file "${ENV_FILE}" "${EXTRA[@]}"
