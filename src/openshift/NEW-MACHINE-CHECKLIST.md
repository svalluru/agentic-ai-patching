# New machine checklist — OpenShift + remote AAP

Use this when moving to a **new laptop/workstation** and/or a **new OpenShift cluster**, while keeping the **same remote Ansible AAP** and GitHub playbook repo.

The app runs **in the cluster**. Your machine only needs `oc` and this bundle.

---

## Before you start

| Check | Command / note |
|-------|----------------|
| [ ] Bundle on the machine | `git clone` or copy the bundle directory |
| [ ] `oc` installed | `oc version` |
| [ ] Logged into **new** cluster | `oc login https://api.<cluster>...` then `oc whoami` |
| [ ] Llama Stack operator | `oc get crd llamastackdistributions.llamastack.io` |
| [ ] Default StorageClass | `oc get sc` — needed for Milvus / Postgres / console PVCs |
| [ ] Inference reachable from cluster | KServe/vLLM on this cluster **or** external MaaS (`VLLM_URL`) |
| [ ] Cluster → remote AAP (HTTPS) | Firewall/route from pod network to AAP controller |
| [ ] Cluster outbound HTTPS | GitHub, `console.redhat.com`, `sso.redhat.com` |

---

## Configure (reuse vs new)

### Copy env template

```bash
cd /path/to/agentic-patching-console-bundle-*
cp openshift/.env.openshift.example openshift/.env.openshift
```

Use **`KEY=value`** syntax only (not YAML `KEY: value`).

### Usually **reuse** (same remote AAP / org)

| Variable | Source |
|----------|--------|
| `AAP_BASE_URL`, `AAP_TOKEN` | Same AAP controller |
| `AAP_DEFAULT_PROJECT_ID`, `INVENTORY_ID`, `EXECUTION_ENVIRONMENT_ID`, `ORGANIZATION_ID` | Same AAP object IDs |
| `AAP_VERIFY_TLS` | `false` for sandbox / self-signed AAP |
| `LIGHTSPEED_CLIENT_ID`, `LIGHTSPEED_CLIENT_SECRET` | Same Insights service account |
| `GIT_HUB_TOKEN` | Same GitHub PAT (`repo` scope) |

Also confirm in **`openshift/cve-console/configmap.yaml`**:

- `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `GITHUB_REPO_BRANCH`
- Same `AAP_DEFAULT_*` IDs as `.env.openshift`
- `CVE_CONSOLE_CVE_LIST_SOURCE: "direct_mcp"`

### **New per cluster** (do not copy from old cluster)

| Item | Action |
|------|--------|
| `VLLM_URL`, `VLLM_API_TOKEN` | Endpoint reachable **from this cluster’s pods** |
| `VECTOR_DB_ID` | Set to `""` before first deploy; filled after RAG ingest |
| Milvus / vector store | Created fresh on this cluster |
| Console Route URL | New hostname after deploy |

---

## Deploy

```bash
chmod +x openshift/scripts/*.sh
./openshift/scripts/setup-openshift.sh
```

Options:

```bash
./openshift/scripts/setup-openshift.sh -y              # skip confirmation
./openshift/scripts/setup-openshift.sh --skip-rag      # infra + console only; RAG later
./openshift/scripts/setup-openshift.sh --skip-build    # image already on cluster
```

If RAG was skipped, run later:

```bash
./openshift/scripts/rerun-rag-ingest.sh
# then patch VECTOR_DB_ID and restart console (setup script does this automatically when RAG runs in full setup)
```

---

## Verify

```bash
oc get pods -n agentic-patching
oc get llamastackdistribution agentic-patching-llsd -n agentic-patching
oc get route cve-console -n agentic-patching -o jsonpath='https://{.spec.host}{"\n"}'
oc logs -f deploy/cve-console -n agentic-patching
```

| Check | Expected |
|-------|----------|
| [ ] All pods Running / LSD Ready | Milvus, postgres, insights-mcp, cve-console |
| [ ] RAG ingest complete | Logs show `ALL ROWS INDEXED` or `Completed files: N/N` |
| [ ] `VECTOR_DB_ID` set | In `cve-console-config` ConfigMap (`vs_...`) |
| [ ] AAP ping from pod | Setup script checks this (or run manually — see OPENSHIFT-DEPLOY.md §7) |
| [ ] UI opens | CVEs tab loads |
| [ ] Patch flow | Start Patch → playbook → GitHub → AAP job/workflow |

---

## What stays external (unchanged)

- **Remote AAP** controller — no redeploy on OpenShift
- **GitHub** playbook repo — AAP project still syncs from it
- **Lightspeed** service account — same creds unless rotated

## What is **not** portable

- Old cluster `VECTOR_DB_ID` — invalid on new Milvus; **re-run RAG ingest**
- Old Llama Stack / Milvus data — new cluster starts empty
- Committed secret YAML — use `openshift/.env.openshift` + `apply-secrets.sh` only

---

## Troubleshooting

| Issue | See |
|-------|-----|
| Full deploy details | [OPENSHIFT-DEPLOY.md](OPENSHIFT-DEPLOY.md) |
| LSD not Ready | `./openshift/scripts/diagnose-llsd.sh` |
| RAG failed / partial | `./openshift/scripts/rerun-rag-ingest.sh` |
| Tear down cluster only | `./openshift/scripts/cleanup-openshift.sh` |
| Local dev (not OpenShift) | [../local/README.md](../local/README.md) |

---

## One-liner summary

**New machine:** `oc login` → copy bundle → fill `openshift/.env.openshift` → clear `VECTOR_DB_ID` → `./openshift/scripts/setup-openshift.sh` → open route → patch a CVE.
