# Check in console code under `src/` to GitHub

Target repo: [https://github.com/svalluru/agentic-ai-patching](https://github.com/svalluru/agentic-ai-patching)

Layout on GitHub (monorepo):

```
agentic-ai-patching/
├── playbooks/          # existing — AAP sync (unchanged)
├── scripts/            # existing playbook helpers
├── README.md           # repo root readme (merge with this project README)
└── src/                # console application + OpenShift manifests
    ├── local/
    ├── openshift/
    └── README.md
```

## One-time setup

### 1. Clone the GitHub repo

```bash
cd /Users/svalluru/githubprojs/agentic-patching
git clone https://github.com/svalluru/agentic-ai-patching.git agentic-ai-patching-github
cd agentic-ai-patching-github
```

### 2. Copy `src/` from your working tree

```bash
rsync -a --delete \
  --exclude='local/agentic-ai-patching' \
  --exclude='local/agentic-ai-patching.bak' \
  --exclude='local/cve_console/.env' \
  --exclude='openshift/.env.openshift' \
  --exclude='local/cve_console/state.json' \
  --exclude='local/playbooks/generated' \
  --exclude='**/__pycache__' \
  --exclude='**/.DS_Store' \
  /Users/svalluru/githubprojs/agentic-patching/oc/agentic-patching/src/ \
  ./src/
```

Copy repo-level files (first time only):

```bash
cp /Users/svalluru/githubprojs/agentic-patching/oc/agentic-patching/.gitignore ./.gitignore.console
# Merge .gitignore lines into repo .gitignore manually, or:
cat /Users/svalluru/githubprojs/agentic-patching/oc/agentic-patching/.gitignore >> .gitignore
sort -u .gitignore -o .gitignore
```

Update root `README.md` to mention `src/` (use `oc/agentic-patching/README.md` as template).

### 3. Verify no secrets

```bash
git status
git diff | grep -E 'sk-[A-Za-z0-9]{10}|github_pat_|AAP_TOKEN=' || echo "No obvious secrets in diff"
```

### 4. Commit and push

```bash
git add src/ .gitignore README.md
git status
git commit -m "$(cat <<'EOF'
Add agentic patching console under src/.

Console UI, cve_flow, local dev setup, and OpenShift deploy scripts.
Playbooks/ at repo root unchanged for AAP.
EOF
)"
git push origin main
```

## Ongoing updates

After editing code in `oc/agentic-patching/src/`:

```bash
cd /Users/svalluru/githubprojs/agentic-patching/agentic-ai-patching-github

rsync -a --delete \
  --exclude='local/agentic-ai-patching' \
  --exclude='local/cve_console/.env' \
  --exclude='openshift/.env.openshift' \
  --exclude='local/cve_console/state.json' \
  --exclude='local/playbooks/generated' \
  --exclude='**/__pycache__' \
  /Users/svalluru/githubprojs/agentic-patching/oc/agentic-patching/src/ \
  ./src/

git add src/
git commit -m "Update console src"
git push origin main
```

## Work from a single git clone (optional)

Instead of rsync, init git once inside `oc/agentic-patching` and add the playbook repo as remote:

```bash
cd /Users/svalluru/githubprojs/agentic-patching/oc/agentic-patching
git init -b main
git remote add origin https://github.com/svalluru/agentic-ai-patching.git
git fetch origin main
git checkout -b main origin/main   # get existing playbooks/
# ensure src/ is present, then:
git add src/ README.md .gitignore
git commit -m "Add console under src/"
git push origin main
```

If `main` already has history, you may need to merge:

```bash
git pull origin main --allow-unrelated-histories
# resolve conflicts, keep playbooks/ and src/
git push origin main
```

## Paths after check-in

All commands run from **`src/`**:

```bash
git clone https://github.com/svalluru/agentic-ai-patching.git
cd agentic-ai-patching/src
./openshift/scripts/setup-openshift.sh
```

Local dev:

```bash
cd agentic-ai-patching/src/local
python3 cve_console.py
```
