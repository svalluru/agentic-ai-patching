# Local setup (Mac / laptop)

Run the console (`cve_console.py` + `cve_flow.py`) on your machine with local or remote Llama Stack, Milvus, and MCP servers. Ansible AAP can be a **remote** sandbox controller.

## Prerequisites

- Python 3.11+
- Podman or Docker (Milvus, Insights MCP, optional GitHub MCP proxy)
- Red Hat Lightspeed service account (Insights + Remediations)
- GitHub PAT (`repo` scope) for playbook push
- AAP OAuth token + base URL (remote controller is fine)

## 1. Workspace

```bash
cd /path/to/agentic-patching-console-bundle-*/local

git clone https://github.com/svalluru/agentic-ai-patching.git agentic-ai-patching
pip install llama-stack-client sentence-transformers einops mcp
```

Optional local Llama Stack server:

```bash
pip install llama-stack
python3 scripts/patch-milvus-openai-cache.py   # run from local/ — after each llama-stack upgrade
```

## 2. Milvus

Start Milvus standalone (example):

```bash
# your Milvus install dir
bash standalone_embed.sh start
```

Endpoint: `http://localhost:19530`

## 3. Insights MCP

```bash
export LIGHTSPEED_CLIENT_ID=...
export LIGHTSPEED_CLIENT_SECRET=...

podman run --env LIGHTSPEED_CLIENT_ID --env LIGHTSPEED_CLIENT_SECRET \
  -p 8000:8000 --rm \
  ghcr.io/redhatinsights/red-hat-lightspeed-mcp:latest \
  --all-tools http --host 0.0.0.0
```

Endpoint: `http://localhost:8000/mcp`

## 4. GitHub MCP (optional — for `PLAYBOOK_PUSH_METHOD=mcp`)

Remote (simplest):

```env
GITHUB_MCP_ENDPOINT=https://api.githubcopilot.com/mcp/
```

Local SSE bridge:

```bash
pip install mcp-proxy
export GITHUB_PERSONAL_ACCESS_TOKEN=github_pat_...
mcp-proxy --host 0.0.0.0 --port 9800 -- \
  docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN -e GITHUB_TOOLSETS=all \
  ghcr.io/github/github-mcp-server
```

## 5. Llama Stack

Config: `llamastack/run.yaml` (local 0.3.x style). Start:

```bash
cd llamastack && llama stack run run.yaml
```

Listens on `http://127.0.0.1:8321`.

After Insights MCP starts with `--all-tools`, restart Llama Stack and verify remediations tool is indexed.

## 6. RAG ingest (local)

```bash
python3 gpt-ingest.py cve-sample-historical-1000.csv \
  --vector-store-name cve-host-history \
  --batch-size 50 --wait-seconds 30 --until-complete
```

Copy the returned `vs_...` ID into your env file (step 7).

## 7. Console env — `cve_console/.env`

```env
AAP_VERIFY_TLS=false
AAP_TOKEN=YOUR_AAP_TOKEN
AAP_BASE_URL=https://your-remote-aap-host/api/controller/v2

CVE_CONSOLE_HOST=0.0.0.0
CVE_CONSOLE_PORT=8787
LLAMA_STACK_URL=http://127.0.0.1:8321
VECTOR_DB_ID=vs_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

GIT_HUB_TOKEN=github_pat_...
PLAYBOOK_PUSH_METHOD=git
# PLAYBOOK_PUSH_METHOD=mcp

GITHUB_MCP_ENDPOINT=https://api.githubcopilot.com/mcp/
GITHUB_REPO_OWNER=svalluru
GITHUB_REPO_NAME=agentic-ai-patching
GITHUB_REPO_BRANCH=main

LIGHTSPEED_CLIENT_ID=...
LIGHTSPEED_CLIENT_SECRET=...

# CVE tab — fast list without Llama Stack LLM round-trip
CVE_CONSOLE_CVE_LIST_SOURCE=direct_mcp
INSIGHTS_MCP_ENDPOINT=http://localhost:8000/mcp

CVE_CONSOLE_LOG_LEVEL=INFO
CVE_FLOW_LOG_LEVEL=INFO
```

Do not commit `.env`.

## 8. AAP IDs

Set in `cve_console/.env` or patch `cve_flow.py` defaults:

| Env / constant | Purpose |
|----------------|---------|
| `AAP_DEFAULT_PROJECT_ID` | AAP project synced from GitHub repo |
| `AAP_DEFAULT_INVENTORY_ID` | Target inventory |
| `AAP_DEFAULT_EXECUTION_ENVIRONMENT_ID` | EE for job templates |
| `AAP_DEFAULT_ORGANIZATION_ID` | Organization |

Remote AAP: use the same token/URL you use in production; set `AAP_VERIFY_TLS=false` for sandbox TLS.

## 9. Start the console

```bash
cd /path/to/bundle/local
lsof -ti :8787 | xargs kill 2>/dev/null || true

nohup python3 cve_console.py >> cve_console.log 2>&1 &
echo $! > cve_console.pid
```

Open **http://127.0.0.1:8787/** — tabs: **Patch Runs**, **CVEs**.

## 10. Run flow manually

```bash
python3 cve_flow.py --cve CVE-2020-25681
```

## Startup order

1. Milvus  
2. Insights MCP (`--all-tools`)  
3. GitHub MCP (if `PLAYBOOK_PUSH_METHOD=mcp`)  
4. Llama Stack  
5. RAG ingest (once)  
6. `cve_console.py`

## Logs

```bash
tail -f cve_console.log
grep '\[cve-flow\]' cve_console.log
grep '\[cve-console\]' cve_console.log
```

## CVE list sources (`CVE_CONSOLE_CVE_LIST_SOURCE`)

| Value | Behavior |
|-------|----------|
| `direct_mcp` | HTTP MCP to `INSIGHTS_MCP_ENDPOINT` — **recommended** locally |
| `rest` | `console.redhat.com` vulnerability API (OAuth via Lightspeed creds) |
| `llama` | Llama Stack `/v1/responses` — slow; avoid for CVE tab |

Patch flow always uses Llama Stack MCP for `get_cve`, systems, remediations (on RHOAI 0.7).

## Troubleshooting (local)

| Symptom | Fix |
|---------|-----|
| CVE tab slow / MCP errors | `CVE_CONSOLE_CVE_LIST_SOURCE=direct_mcp` |
| RAG empty after Llama restart | Re-run Milvus patch + `gpt-ingest.py` |
| Git push identity error | `git config user.name` / `user.email` in `agentic-ai-patching` |
| AAP SSL error | `AAP_VERIFY_TLS=false` |
| `list-tools` 404 on RHOAI 0.7 | Local 0.3.x only — cluster uses `/v1/responses` (see OpenShift doc) |

For cluster deployment see **[../openshift/OPENSHIFT-DEPLOY.md](../openshift/OPENSHIFT-DEPLOY.md)**.
