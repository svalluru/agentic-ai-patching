# Agentic Patching Console

CVE patching workflow: **Insights → RAG → LLM → playbook → GitHub → AAP**, with operator UI.

## Layout

```
src/
├── local/          Application + local Mac/laptop setup
├── openshift/      Cluster deploy (OpenShift / RHOAI + remote AAP)
└── README.md       This file
```

Run commands below from **`src/`** (repository root is one level up in the monorepo).

| Environment | Start here |
|-------------|------------|
| **New laptop + OpenShift cluster** | [openshift/NEW-MACHINE-CHECKLIST.md](openshift/NEW-MACHINE-CHECKLIST.md) |
| **OpenShift deploy (full guide)** | [openshift/OPENSHIFT-DEPLOY.md](openshift/OPENSHIFT-DEPLOY.md) |
| **Local dev on Mac/laptop** | [local/README.md](local/README.md) |
| **Scripts index** | [openshift/README.md](openshift/README.md) |

## Application (in `local/`)

| File | Role |
|------|------|
| `local/cve_console.py` | Web UI + API (`:8787`) |
| `local/cve_flow.py` | Patch orchestration |
| `local/gpt-ingest.py` | Local RAG ingest (CSV → vector store) |
| `local/cve-sample-historical-1000.csv` | Sample RAG data (also baked into cluster image) |

Legacy v3 scripts: `local/legacy/`

## Quick start

**OpenShift (from `src/`):**

```bash
cd src
cp openshift/.env.openshift.example openshift/.env.openshift   # edit secrets
./openshift/scripts/setup-openshift.sh
```

**Local:**

```bash
cd src/local
# configure cve_console/.env — see local/README.md
python3 cve_console.py
```
