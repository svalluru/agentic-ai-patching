# agentic-ai-patching

Repository for AI-generated patching automation content intended for AWX/Automation Controller consumption.

## Layout

- `playbooks/` - top-level playbooks that AWX can launch
- `scripts/` - helper scripts for generating, committing, and pushing content
- `artifacts/` - generated metadata/manifests if needed

## Initial pattern

This repo starts with a generic bootstrap playbook path so AWX can sync a stable project while generated content can be added over time.
