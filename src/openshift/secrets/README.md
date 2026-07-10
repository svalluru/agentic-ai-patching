# Secrets (cluster-only)

Secrets are **not** applied from YAML in this repo. Use the env file + script:

```bash
cp ../.env.openshift.example ../.env.openshift   # edit values — do not commit
../scripts/apply-secrets.sh
```

Or run full setup: `../scripts/setup-openshift.sh`

## Secret names and keys

| Secret | Keys |
|--------|------|
| `agentic-patching-app-secret` | `AAP_TOKEN`, `AAP_BASE_URL`, `GIT_HUB_TOKEN`, `LIGHTSPEED_CLIENT_ID`, `LIGHTSPEED_CLIENT_SECRET` |
| `llama-stack-inference-model-secret` | `VLLM_URL`, `VLLM_API_TOKEN`, `INFERENCE_MODEL`, `VLLM_TLS_VERIFY` |
| `llamastack-postgres-secret` | `password` (optional `POSTGRES_PASSWORD` in env, default `changeme`) |
| `milvus-secret` | `root-password`, `MILVUS_ENDPOINT`, `MILVUS_TOKEN`, `MILVUS_CONSISTENCY_LEVEL` |

Example manifests (placeholders only): `*.yaml.example` in this directory.

Production: prefer Sealed Secrets or External Secrets instead of plain env files.
