# Legacy (v3) — reference only

Pre–OpenShift-console snapshot of the patching UI and flow. **Not deployed.**

| File | Role |
|------|------|
| `cve_console_v3.py` | Older web UI (~655 lines) |
| `cve_flow_v3.py` | Older orchestration script |

**Use instead:** `local/cve_console.py` + `local/cve_flow.py` (OpenShift + current local dev).

## Optional local run

From **`local/`** (uses `cve_console/.env` and state in that directory):

```bash
cd local
python3 legacy/cve_console_v3.py
python3 legacy/cve_flow_v3.py --cve CVE-2020-25681
```

Set `WORKSPACE=/path/to/local` if you run from another directory.
