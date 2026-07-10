#!/usr/bin/env python3
"""Re-index an existing Llama Stack vector store into Milvus without re-uploading files.

Use when file_counts show completed rows but Milvus search fails (cache #5209 or empty Milvus).
Collects file IDs already attached to SOURCE_STORE_ID, creates a new vector store, and attaches
them with the same static chunking strategy as ingest (embed + insert only).

Prerequisite: uploaded files must still exist at GET /v1/files/{id}. If LSD used ephemeral
storage (emptyDir), files are gone and you must run full production CSV ingest instead.
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def http_json(method: str, url: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read().decode()
        return json.loads(body) if body else None


def list_vector_store_file_ids(endpoint: str, store_id: str) -> list[str]:
    ids: list[str] = []
    after = None
    while True:
        url = f"{endpoint}/v1/vector_stores/{store_id}/files?limit=100"
        if after:
            url += f"&after={after}"
        page = http_json("GET", url)
        for item in page.get("data", []) or []:
            fid = item.get("id")
            if fid:
                ids.append(fid)
        if not page.get("has_more"):
            break
        after = page.get("last_id") or (page.get("data") or [{}])[-1].get("id")
        if not after:
            break
    return ids


def file_exists(endpoint: str, file_id: str) -> bool:
    try:
        http_json("GET", f"{endpoint}/v1/files/{file_id}")
        return True
    except urllib.error.HTTPError:
        return False


def discover_embedding(endpoint: str) -> tuple[str, int]:
    raw = http_json("GET", f"{endpoint}/v1/models")
    for item in raw.get("data", []) or []:
        meta = item.get("metadata") or item.get("custom_metadata") or {}
        if meta.get("model_type") == "embedding" or meta.get("embedding_dimension"):
            mid = item.get("id") or item.get("identifier")
            dim = int(meta.get("embedding_dimension") or 768)
            return mid, dim
    raise RuntimeError("No embedding model in /v1/models")


def create_store(endpoint: str, name: str, embedding_model: str, embedding_dim: int, provider_id: str) -> str:
    payload = {
        "name": name,
        "provider_id": provider_id,
        "embedding_model": embedding_model,
        "embedding_dimension": embedding_dim,
    }
    store = http_json("POST", f"{endpoint}/v1/vector_stores", payload)
    return store["id"]


def attach_file(endpoint: str, store_id: str, file_id: str, chunk_size: int) -> dict:
    payload = {
        "file_id": file_id,
        "chunking_strategy": {
            "type": "static",
            "static": {
                "max_chunk_size_tokens": chunk_size,
                "chunk_overlap_tokens": 0,
            },
        },
    }
    return http_json("POST", f"{endpoint}/v1/vector_stores/{store_id}/files", payload)


def get_store(endpoint: str, store_id: str) -> dict:
    return http_json("GET", f"{endpoint}/v1/vector_stores/{store_id}")


def wait_store_progress(
    endpoint: str,
    store_id: str,
    target_completed: int,
    timeout: int,
    poll: int,
) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        store = get_store(endpoint, store_id)
        fc = store.get("file_counts", {})
        completed = int(fc.get("completed", 0) or 0)
        failed = int(fc.get("failed", 0) or 0)
        in_progress = int(fc.get("in_progress", 0) or 0)
        print(f"Store progress: completed={completed} failed={failed} in_progress={in_progress}")
        if failed > 0 and in_progress == 0:
            return store
        if completed >= target_completed and in_progress == 0:
            return store
        time.sleep(poll)
    return get_store(endpoint, store_id)


def main():
    p = argparse.ArgumentParser(description="Re-index existing vector store files into Milvus")
    p.add_argument("--endpoint", default="http://127.0.0.1:8321")
    p.add_argument("--source-store-id", required=True, help="Existing store with completed files")
    p.add_argument("--target-store-id", help="Reuse this store instead of creating a new one")
    p.add_argument("--store-name", default="cve-host-history-reindex")
    p.add_argument("--provider-id", default="milvus-remote")
    p.add_argument("--batch-size", type=int, default=50, help="Files to attach before waiting for indexing")
    p.add_argument("--chunk-size", type=int, default=4096, help="max_chunk_size_tokens (match ingest)")
    p.add_argument("--batch-timeout", type=int, default=1800, help="Seconds to wait per attach batch")
    p.add_argument("--poll-interval", type=int, default=10)
    args = p.parse_args()

    print(f"Source store: {args.source_store_id}")
    source = get_store(args.endpoint, args.source_store_id)
    completed = int((source.get("file_counts") or {}).get("completed", 0) or 0)
    print(f"Source completed files: {completed}")

    file_ids = list_vector_store_file_ids(args.endpoint, args.source_store_id)
    print(f"Collected {len(file_ids)} file IDs from source store")
    if not file_ids:
        print("ERROR: no files on source store — run full ingest first", file=sys.stderr)
        sys.exit(1)

    sample = file_ids[: min(5, len(file_ids))]
    missing = [fid for fid in sample if not file_exists(args.endpoint, fid)]
    if missing:
        print(
            "ERROR: uploaded files are missing from /v1/files (LSD likely lost ephemeral storage).\n"
            f"  Sample missing: {missing[:3]}\n"
            "  Fix: apply openshift/llamastack/ with server.storage PVC, then run full CSV ingest.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.target_store_id:
        target_id = args.target_store_id
        print(f"Target store (existing): {target_id}")
    else:
        emb, dim = discover_embedding(args.endpoint)
        print(f"Creating target store (embedding={emb}, dim={dim})...")
        target_id = create_store(args.endpoint, args.store_name, emb, dim, args.provider_id)
        print(f"Target store ID: {target_id}")

    attached = 0
    for i in range(0, len(file_ids), args.batch_size):
        chunk = file_ids[i : i + args.batch_size]
        print(f"Attach batch {i // args.batch_size + 1}: {len(chunk)} files...")
        for fid in chunk:
            attach_file(args.endpoint, target_id, fid, args.chunk_size)
        attached += len(chunk)
        store = wait_store_progress(
            args.endpoint,
            target_id,
            target_completed=attached,
            timeout=args.batch_timeout,
            poll=args.poll_interval,
        )
        fc = store.get("file_counts", {})
        failed = int(fc.get("failed", 0) or 0)
        if failed > 0:
            print(f"ERROR: {failed} files failed during re-index: {json.dumps(fc)}", file=sys.stderr)
            sys.exit(1)

    final = get_store(args.endpoint, target_id)
    fc = final.get("file_counts", {})
    print("\nRe-index complete.")
    print(f"Target vector store ID: {target_id}")
    print(f"File counts: {json.dumps(fc)}")
    print("\nUpdate cve-console-config:")
    print(f'  VECTOR_DB_ID: "{target_id}"')


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        print(f"HTTP error {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
