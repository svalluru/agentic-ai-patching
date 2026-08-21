#!/usr/bin/env python3
"""Create/update an AAP project synced from the GitHub playbook repo (no UI).

Reads AAP_*/GIT_HUB_TOKEN/GITHUB_REPO_* from the environment (typically via
openshift/.env.openshift through setup-aap-project.sh).

Uses AAP_PROJECT_NAME to create (or update by name) the project, then writes
AAP_DEFAULT_PROJECT_ID back into the env file and patches the console ConfigMap
when possible.

Examples:
  ./openshift/scripts/setup-aap-project.sh
  ./openshift/scripts/setup-aap-project.sh --sync-only
  ./openshift/scripts/setup-aap-project.sh --project-id 6
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_OWNER = "svalluru"
DEFAULT_REPO = "agentic-ai-patching"
DEFAULT_BRANCH = "main"
DEFAULT_PROJECT_NAME = "agentic-ai-patching"
DEFAULT_CREDENTIAL_NAME = "agentic-ai-patching-github-scm"


def load_dotenv(path: str) -> None:
    if not path or not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def update_env_key(path: str, key: str, value: str) -> None:
    """Set KEY=value in a KEY=value env file (insert or replace)."""
    if not path:
        raise SystemExit("Cannot update env file: --env-file not set")
    if not os.path.isfile(path):
        raise SystemExit(f"Cannot update env file: not found: {path}")

    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()

    pattern = re.compile(rf"^{re.escape(key)}=")
    replaced = False
    out: list[str] = []
    for line in lines:
        if pattern.match(line):
            out.append(f"{key}={value}\n")
            replaced = True
        else:
            out.append(line if line.endswith("\n") else line + "\n")

    if not replaced:
        # Insert after AAP_PROJECT_NAME if present, else after AAP_TOKEN, else append.
        insert_at = len(out)
        for i, line in enumerate(out):
            if line.startswith("AAP_PROJECT_NAME=") or line.startswith("AAP_TOKEN="):
                insert_at = i + 1
        out.insert(insert_at, f"{key}={value}\n")

    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(out)
    print(f"Updated {path}: {key}={value}")


def aap_base() -> str:
    raw = (
        os.environ.get("AAP_BASE_URL")
        or os.environ.get("AAP_URL")
        or os.environ.get("CONTROLLER_HOST")
        or ""
    ).strip()
    if not raw:
        raise SystemExit("AAP_BASE_URL is required")
    if "/api/controller/" in raw:
        raw = raw.split("/api/controller/")[0]
    return raw.rstrip("/")


def verify_tls() -> bool:
    return os.environ.get("AAP_VERIFY_TLS", "false").lower() in {"1", "true", "yes"}


def ssl_context():
    if verify_tls():
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def aap_req(method: str, path: str, payload: Any = None, params: dict | None = None) -> Any:
    token = (
        os.environ.get("AAP_TOKEN")
        or os.environ.get("CONTROLLER_OAUTH_TOKEN")
        or os.environ.get("AWX_TOKEN")
        or ""
    ).strip()
    if not token:
        raise SystemExit("AAP_TOKEN is required")

    base = aap_base()
    url = f"{base}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"

    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl_context()) as resp:
            body = resp.read().decode()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")
        raise SystemExit(f"AAP {method} {path} -> HTTP {exc.code}: {err_body}") from exc


def org_id() -> int:
    return int(os.environ.get("AAP_DEFAULT_ORGANIZATION_ID", "1"))


def repo_settings() -> tuple[str, str, str, str]:
    owner = os.environ.get("GITHUB_REPO_OWNER", DEFAULT_OWNER).strip() or DEFAULT_OWNER
    repo = os.environ.get("GITHUB_REPO_NAME", DEFAULT_REPO).strip() or DEFAULT_REPO
    branch = os.environ.get("GITHUB_REPO_BRANCH", DEFAULT_BRANCH).strip() or DEFAULT_BRANCH
    scm_url = os.environ.get("AAP_PROJECT_SCM_URL", "").strip()
    if not scm_url:
        scm_url = f"https://github.com/{owner}/{repo}.git"
    return owner, repo, branch, scm_url


def find_scm_credential_type_id() -> int:
    data = aap_req("GET", "/api/controller/v2/credential_types/", params={"kind": "scm", "page_size": "20"})
    results = (data or {}).get("results") or []
    if not results:
        raise SystemExit("No Source Control (scm) credential type found on this AAP")
    return int(results[0]["id"])


def ensure_scm_credential(name: str, github_token: str) -> int:
    """Create or update a Source Control credential using the GitHub PAT."""
    cred_type = find_scm_credential_type_id()
    existing = aap_req(
        "GET",
        "/api/controller/v2/credentials/",
        params={"name": name, "organization": str(org_id()), "page_size": "5"},
    )
    results = (existing or {}).get("results") or []
    payload = {
        "name": name,
        "description": "GitHub PAT for agentic playbook repo (managed by setup-aap-project.py)",
        "organization": org_id(),
        "credential_type": cred_type,
        "inputs": {
            "username": "x-access-token",
            "password": github_token,
        },
    }
    if results:
        cred_id = int(results[0]["id"])
        print(f"Updating SCM credential id={cred_id} name={name}")
        aap_req("PATCH", f"/api/controller/v2/credentials/{cred_id}/", payload=payload)
        return cred_id

    print(f"Creating SCM credential name={name}")
    created = aap_req("POST", "/api/controller/v2/credentials/", payload=payload)
    return int(created["id"])


def find_project_by_id(project_id: int) -> dict | None:
    try:
        return aap_req("GET", f"/api/controller/v2/projects/{project_id}/")
    except SystemExit as exc:
        if "HTTP 404" in str(exc):
            return None
        raise


def find_project_by_name(name: str) -> dict | None:
    by_name = aap_req(
        "GET",
        "/api/controller/v2/projects/",
        params={"name": name, "organization": str(org_id()), "page_size": "20"},
    )
    for item in (by_name or {}).get("results") or []:
        if item.get("name") == name:
            return item
    return None


def ensure_project(
    *,
    project_id: int | None,
    name: str,
    scm_url: str,
    branch: str,
    credential_id: int,
    force_create: bool,
) -> dict:
    """Create a project named `name`, or update the matching one.

    Lookup order:
      1. --project-id if given
      2. exact name match in the org (AAP_PROJECT_NAME)
    Does not reuse a different project just because SCM URL matches.
    """
    existing: dict | None = None
    if project_id and not force_create:
        existing = find_project_by_id(project_id)
        if existing is None:
            raise SystemExit(f"Project id={project_id} not found")
    elif not force_create:
        existing = find_project_by_name(name)

    payload = {
        "name": name,
        "description": "Playbook repo for agentic CVE patching (managed by setup-aap-project.py)",
        "organization": org_id(),
        "scm_type": "git",
        "scm_url": scm_url,
        "scm_branch": branch,
        "scm_clean": False,
        "scm_delete_on_update": False,
        "scm_update_on_launch": False,
        "scm_update_cache_timeout": 0,
        "allow_override": False,
        "credential": credential_id,
    }
    if existing and not force_create:
        pid = int(existing["id"])
        print(f"Updating project id={pid} name={existing.get('name')} -> {name}")
        return aap_req("PATCH", f"/api/controller/v2/projects/{pid}/", payload=payload)

    print(f"Creating project name={name} scm_url={scm_url} branch={branch}")
    return aap_req("POST", "/api/controller/v2/projects/", payload=payload)


def wait_for_project_update(update_id: int, timeout_seconds: int = 300) -> dict:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        update = aap_req("GET", f"/api/controller/v2/project_updates/{update_id}/")
        status = update.get("status")
        print(f"  project_update id={update_id} status={status}")
        if status in {"successful", "failed", "error", "canceled"}:
            return update
        time.sleep(3)
    raise SystemExit(f"Timed out waiting for project_update id={update_id}")


def sync_project(project_id: int) -> dict:
    print(f"Syncing project id={project_id} ...")
    launch = aap_req("POST", f"/api/controller/v2/projects/{project_id}/update/", payload={})
    update_id = launch.get("project_update") or launch.get("id")
    if not update_id:
        raise SystemExit(f"Could not determine project_update id from: {launch}")
    update = wait_for_project_update(int(update_id))
    if update.get("status") != "successful":
        raise SystemExit(f"Project sync failed: status={update.get('status')} detail={json.dumps(update)[:800]}")
    print("Sync successful")
    return update


def list_playbooks(project_id: int) -> list[str]:
    data = aap_req("GET", f"/api/controller/v2/projects/{project_id}/playbooks/")
    if isinstance(data, list):
        return [str(x) for x in data]
    if isinstance(data, dict):
        for key in ("playbooks", "results"):
            if key in data and isinstance(data[key], list):
                return [str(x) for x in data[key]]
    return []


def patch_console_project_id(project_id: int, namespace: str) -> None:
    if not shutil.which("oc"):
        print("oc not found; skip ConfigMap patch (update AAP_DEFAULT_PROJECT_ID manually if needed)")
        return
    patch = json.dumps({"data": {"AAP_DEFAULT_PROJECT_ID": str(project_id)}})
    cmd = [
        "oc",
        "patch",
        "configmap",
        "cve-console-config",
        "-n",
        namespace,
        "--type",
        "merge",
        "-p",
        patch,
    ]
    print(f"Patching configmap/cve-console-config in namespace {namespace} ...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"WARNING: ConfigMap patch failed (console may not be deployed yet):\n"
            f"{result.stderr or result.stdout}",
            file=sys.stderr,
        )
        return
    print(result.stdout.strip() or "configmap patched")
    restart = subprocess.run(
        ["oc", "rollout", "restart", "deployment/cve-console", "-n", namespace],
        capture_output=True,
        text=True,
    )
    if restart.returncode != 0:
        print(
            f"WARNING: rollout restart failed:\n{restart.stderr or restart.stdout}",
            file=sys.stderr,
        )
    else:
        print(restart.stdout.strip() or "deployment/cve-console restarted")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create/update + sync AAP project from GitHub playbook repo")
    p.add_argument("--env-file", default="", help="Optional .env file to load/update (KEY=value)")
    p.add_argument("--project-id", type=int, default=None, help="Update/sync this existing project id")
    p.add_argument("--project-name", default="", help="Override AAP_PROJECT_NAME")
    p.add_argument("--credential-name", default="", help="Override AAP_SCM_CREDENTIAL_NAME")
    p.add_argument(
        "--force-create",
        action="store_true",
        help="Always POST a new project (even if AAP_PROJECT_NAME already exists)",
    )
    p.add_argument("--sync-only", action="store_true", help="Only sync an existing project id")
    p.add_argument("--no-sync", action="store_true", help="Create/update project but skip sync")
    p.add_argument(
        "--skip-env-update",
        action="store_true",
        help="Do not write AAP_DEFAULT_PROJECT_ID back to the env file",
    )
    p.add_argument(
        "--skip-console-patch",
        action="store_true",
        help="Do not patch cve-console-config / restart deployment",
    )
    p.add_argument("--print-env", action="store_true", help="Print AAP_DEFAULT_PROJECT_ID=<id>")
    return p.parse_args()


def resolve_project_name(args: argparse.Namespace) -> str:
    name = (args.project_name or os.environ.get("AAP_PROJECT_NAME") or "").strip()
    if not name:
        name = DEFAULT_PROJECT_NAME
        print(f"WARNING: AAP_PROJECT_NAME not set; using default name={name}", file=sys.stderr)
    return name


def resolve_credential_name(args: argparse.Namespace, project_name: str) -> str:
    name = (args.credential_name or os.environ.get("AAP_SCM_CREDENTIAL_NAME") or "").strip()
    if name:
        return name
    return f"{project_name}-github-scm"


def print_playbooks(project_id: int) -> list[str]:
    playbooks = list_playbooks(project_id)
    print(f"Playbooks visible to AAP ({len(playbooks)}):")
    for path in playbooks[:40]:
        print(f"  - {path}")
    if len(playbooks) > 40:
        print(f"  ... and {len(playbooks) - 40} more")
    if not any(p.startswith("playbooks/") for p in playbooks):
        print(
            "WARNING: no playbooks/ paths found. Confirm the GitHub repo root "
            "contains playbooks/ and the branch is correct.",
            file=sys.stderr,
        )
    return playbooks


def persist_project_id(project_id: int, args: argparse.Namespace) -> None:
    if args.env_file and not args.skip_env_update:
        update_env_key(args.env_file, "AAP_DEFAULT_PROJECT_ID", str(project_id))
        os.environ["AAP_DEFAULT_PROJECT_ID"] = str(project_id)
    elif not args.skip_env_update:
        print("WARNING: no --env-file; skipped writing AAP_DEFAULT_PROJECT_ID", file=sys.stderr)

    if not args.skip_console_patch:
        namespace = os.environ.get("NAMESPACE", "agentic-patching").strip() or "agentic-patching"
        patch_console_project_id(project_id, namespace)

    if args.print_env:
        print(f"AAP_DEFAULT_PROJECT_ID={project_id}")


def main() -> int:
    args = parse_args()
    if args.env_file:
        load_dotenv(args.env_file)

    owner, repo, branch, scm_url = repo_settings()
    project_name = resolve_project_name(args)
    credential_name = resolve_credential_name(args, project_name)
    github_token = (os.environ.get("GIT_HUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()

    print(f"AAP controller: {aap_base()}")
    print(f"Organization:   {org_id()}")
    print(f"Project name:   {project_name}")
    print(f"GitHub target:  {owner}/{repo}@{branch}")
    print(f"SCM URL:        {scm_url}")

    if args.sync_only:
        project_id = args.project_id
        if not project_id:
            env_id = os.environ.get("AAP_DEFAULT_PROJECT_ID", "").strip()
            if env_id.isdigit():
                project_id = int(env_id)
        if not project_id:
            named = find_project_by_name(project_name)
            if named:
                project_id = int(named["id"])
        if not project_id:
            raise SystemExit("--sync-only needs --project-id, AAP_DEFAULT_PROJECT_ID, or an existing AAP_PROJECT_NAME")
        sync_project(project_id)
        print_playbooks(project_id)
        persist_project_id(project_id, args)
        return 0

    if not github_token:
        raise SystemExit("GIT_HUB_TOKEN is required to create/update the SCM credential")

    cred_id = ensure_scm_credential(credential_name, github_token)
    project = ensure_project(
        project_id=args.project_id,
        name=project_name,
        scm_url=scm_url,
        branch=branch,
        credential_id=cred_id,
        force_create=args.force_create,
    )
    project_id = int(project["id"])
    print(f"Project ready id={project_id} name={project.get('name')}")

    if not args.no_sync:
        sync_project(project_id)

    print_playbooks(project_id)
    persist_project_id(project_id, args)

    print()
    print("Done.")
    print(f"  AAP_PROJECT_NAME={project_name}")
    print(f"  AAP_DEFAULT_PROJECT_ID={project_id}")
    print("  Retry Start Patch in the UI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
