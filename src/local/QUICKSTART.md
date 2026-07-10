# Agentic Patching Console — local quickstart

Run from **`local/`** on your machine. For OpenShift see [../openshift/NEW-MACHINE-CHECKLIST.md](../openshift/NEW-MACHINE-CHECKLIST.md).

## Main files (this directory)

- `cve_flow.py` — end-to-end patch flow
- `cve_console.py` — web console
- `cve_console/.env` — local config (create from README)
- [README.md](README.md) — full local setup
- `legacy/` — older v3 scripts (reference only)

## Minimal config — `cve_console/.env`

```env
AAP_VERIFY_TLS=false
AAP_TOKEN=YOUR_TOKEN
AAP_BASE_URL=https://your-aap-controller.example.com/api/controller/v2
CVE_CONSOLE_HOST=127.0.0.1
CVE_CONSOLE_PORT=8787
LLAMA_STACK_URL=http://127.0.0.1:8321
VECTOR_DB_ID=vs_...
GIT_HUB_TOKEN=github_pat_...
```

## Run the console

```bash
cd /path/to/bundle/local
python3 cve_console.py
```

Open **http://127.0.0.1:8787/**

## Run flow without UI

```bash
cd /path/to/bundle/local
python3 cve_flow.py --cve CVE-2020-25681
```

## Full documentation

- [README.md](README.md) — Milvus, MCP, RAG ingest, troubleshooting
- [../README.md](../README.md) — repository index
