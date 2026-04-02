#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <source-playbook.yml> <dest-relative-path-in-repo> [commit-message]" >&2
  exit 1
fi

SRC=$1
DEST=$2
MSG=${3:-"Add generated playbook ${DEST}"}
REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
TOKEN_FILE=${TOKEN_FILE:-$HOME/.secrets/github_token}

if [[ ! -f "$SRC" ]]; then
  echo "Source playbook not found: $SRC" >&2
  exit 2
fi
if [[ ! -f "$TOKEN_FILE" ]]; then
  echo "Token file not found: $TOKEN_FILE" >&2
  exit 3
fi

TOKEN=$(tr -d '\r\n' < "$TOKEN_FILE")
mkdir -p "$REPO_DIR/$(dirname "$DEST")"
cp "$SRC" "$REPO_DIR/$DEST"

cd "$REPO_DIR"
git config user.name "OpenClaw"
git config user.email "openclaw@local"
git add "$DEST"
if git diff --cached --quiet; then
  echo "No changes to commit"
  exit 0
fi
git commit -m "$MSG"
git remote set-url origin "https://x-access-token:${TOKEN}@github.com/svalluru/agentic-ai-patching.git"
GIT_TERMINAL_PROMPT=0 git push origin HEAD

echo "Pushed $DEST"
