# Agentic Patching Console — deployment docs

CVE patching workflow: **Insights → RAG → LLM → playbook → GitHub → AAP** with operator UI (`cve-console`).

| Guide | Use when |
|-------|----------|
| **[NEW-MACHINE-CHECKLIST.md](NEW-MACHINE-CHECKLIST.md)** | **One page** — new laptop + new cluster, same remote AAP |
| **[OPENSHIFT-DEPLOY.md](OPENSHIFT-DEPLOY.md)** | OpenShift / RHOAI cluster with **remote Ansible AAP** (full guide) |
| **[../local/README.md](../local/README.md)** | Mac/laptop: Milvus, Llama Stack, MCP, `cve_console.py` |

## Scripts

| Script | Purpose |
|--------|---------|
| **`scripts/setup-openshift.sh`** | **Full automation** — secrets from `.env.openshift` → infra → build → RAG → route |
| `scripts/apply-secrets.sh` | Apply secrets only (from `.env.openshift`) |
| `scripts/deploy.sh` | Partial deploy (infra + build + console; manual RAG steps) |
| `scripts/cleanup-openshift.sh` | Remove stack from OpenShift cluster only |
| `scripts/build-console-image.sh` | Build image from `local/` app sources |
| `scripts/diagnose-llsd.sh` | Llama Stack distribution troubleshooting |
| `scripts/rerun-rag-ingest.sh` | Update ingest scripts + restart `rag-ingest` job |

**Quick start (from `src/`):**

```bash
cd src
cp openshift/.env.openshift.example openshift/.env.openshift   # edit secrets / AAP / vLLM
./openshift/scripts/setup-openshift.sh
```

## Layout (under `src/` in monorepo)

```
src/
├── local/                  # Application + local dev
├── openshift/              # Cluster manifests, scripts
│   ├── cve-console/
│   ├── jobs/
│   ├── milvus/ mcp/ llamastack/
│   └── secrets/            # *.yaml.example
└── README.md
```

Application source lives in **`local/`**; the OpenShift image copies from there at build time.
