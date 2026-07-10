# agentic-ai-patching

This repository serves two roles:

| Path | Purpose |
|------|---------|
| **`playbooks/`** | Ansible playbooks — synced by **AAP** (do not relocate) |
| **`scripts/`** | Helper scripts for playbook repo |
| **`src/`** | **Agentic Patching Console** — UI, flow, OpenShift deploy |

## Console (under `src/`)

CVE workflow: **Insights → RAG → LLM → playbook → GitHub → AAP**.

| Guide | Location |
|-------|----------|
| Console overview | [src/README.md](src/README.md) |
| Local Mac/laptop | [src/local/README.md](src/local/README.md) |
| OpenShift + remote AAP | [src/openshift/OPENSHIFT-DEPLOY.md](src/openshift/OPENSHIFT-DEPLOY.md) |
| New machine checklist | [src/openshift/NEW-MACHINE-CHECKLIST.md](src/openshift/NEW-MACHINE-CHECKLIST.md) |

### Quick start (OpenShift)

```bash
cd src
cp openshift/.env.openshift.example openshift/.env.openshift   # edit secrets
./openshift/scripts/setup-openshift.sh
```

### Quick start (local)

```bash
cd src/local
# configure cve_console/.env — see README.md
python3 cve_console.py
```

## Check in `src/` to GitHub

See [CHECKIN.md](CHECKIN.md).
