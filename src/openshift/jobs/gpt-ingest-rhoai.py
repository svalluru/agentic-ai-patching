#!/usr/bin/env python3
"""Ingest CSV rows into RHOAI 0.7 via OpenAI-compatible Files + Vector Store Files APIs."""

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

DEFAULT_TIMEOUT = int(__import__("os").environ.get("LLAMA_HTTP_TIMEOUT", "300"))
MAX_RETRIES = int(__import__("os").environ.get("LLAMA_HTTP_RETRIES", "5"))
RETRY_WAIT = int(__import__("os").environ.get("LLAMA_HTTP_RETRY_WAIT", "10"))


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in {408, 429, 500, 502, 503, 504}
    if isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionResetError, BrokenPipeError)):
        return True
    msg = str(exc).lower()
    return "goaway" in msg or "connection" in msg or "reset" in msg or "timed out" in msg


def http_json(method: str, url: str, payload=None, extra_headers=None, timeout: int | None = None):
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    headers = {"Content-Type": "application/json", "Connection": "close"}
    if extra_headers:
        headers.update(extra_headers)
    data = None if payload is None else json.dumps(payload).encode()
    last_exc: BaseException | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode()
                return r.status, json.loads(body) if body else None
        except Exception as exc:
            last_exc = exc
            if attempt >= MAX_RETRIES or not _retryable(exc):
                raise
            print(
                f"HTTP {method} {url} failed ({exc}); retry {attempt}/{MAX_RETRIES} in {RETRY_WAIT}s",
                file=sys.stderr,
            )
            time.sleep(RETRY_WAIT)
    raise last_exc  # type: ignore[misc]


def multipart_upload(endpoint: str, filename: str, content: bytes, purpose: str = "assistants"):
    boundary = f"----LlamaStackBoundary{uuid.uuid4().hex}"
    parts = [
        f"--{boundary}\r\n".encode(),
        b'Content-Disposition: form-data; name="purpose"\r\n\r\n',
        f"{purpose}\r\n".encode(),
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: text/plain\r\n\r\n",
        content,
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ]
    body = b"".join(parts)
    last_exc: BaseException | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                f"{endpoint}/v1/files",
                data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Connection": "close",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as r:
                resp = json.loads(r.read().decode())
            return resp["id"]
        except Exception as exc:
            last_exc = exc
            if attempt >= MAX_RETRIES or not _retryable(exc):
                raise
            print(
                f"Upload {filename} failed ({exc}); retry {attempt}/{MAX_RETRIES} in {RETRY_WAIT}s",
                file=sys.stderr,
            )
            time.sleep(RETRY_WAIT)
    raise last_exc  # type: ignore[misc]


def get_file_counts(endpoint: str, vector_store_id: str):
    _, store = http_json("GET", f"{endpoint}/v1/vector_stores/{vector_store_id}")
    file_counts = store.get("file_counts", {})
    completed = int(file_counts.get("completed", 0) or 0)
    in_progress = int(file_counts.get("in_progress", 0) or 0)
    failed = int(file_counts.get("failed", 0) or 0)
    counts = {k: v for k, v in file_counts.items() if k != "total" and v}
    return counts, completed, in_progress, failed, store


def attach_file(endpoint: str, vector_store_id: str, file_id: str, chunk_size: int):
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
    return http_json("POST", f"{endpoint}/v1/vector_stores/{vector_store_id}/files", payload)


def build_documents(csv_path: Path, id_column: str | None, text_columns: list[str] | None):
    docs = []
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            doc_id = row.get(id_column) if id_column else None
            if not doc_id:
                doc_id = f"row-{i}"

            if text_columns:
                parts = [f"{col}: {row.get(col, '')}" for col in text_columns]
            else:
                parts = [f"{k}: {v}" for k, v in row.items()]

            content = "\n".join(parts)
            filename = f"row-{i}.txt"
            docs.append(
                {
                    "document_id": str(doc_id),
                    "content": content.encode("utf-8"),
                    "filename": filename,
                    "row": i,
                }
            )
    return docs


def wait_for_progress(
    endpoint: str,
    vector_store_id: str,
    target_completed: int,
    wait_seconds: int,
    poll_interval: int,
):
    deadline = time.time() + wait_seconds
    last_completed = -1
    while time.time() < deadline:
        counts, completed, in_progress, failed, _ = get_file_counts(endpoint, vector_store_id)
        if completed != last_completed:
            print(
                f"Store progress: completed={completed} in_progress={in_progress} "
                f"failed={failed} target>={target_completed} counts={counts}"
            )
            last_completed = completed
        if completed >= target_completed and in_progress == 0:
            return completed
        time.sleep(poll_interval)
    counts, completed, _, _, _ = get_file_counts(endpoint, vector_store_id)
    return completed


def main():
    p = argparse.ArgumentParser(description="Ingest CSV into RHOAI Llama Stack vector store")
    p.add_argument("csv_path", help="Path to CSV file")
    p.add_argument("--endpoint", default="http://127.0.0.1:8321", help="Llama Stack endpoint")
    p.add_argument("--resume-store-id", required=True, help="Existing vector store id")
    p.add_argument("--batch-size", type=int, default=5, help="Files to upload before waiting for indexing")
    p.add_argument("--chunk-size", type=int, default=4096, help="max_chunk_size_tokens for each uploaded file")
    p.add_argument("--wait-seconds", type=int, default=180, help="Seconds to wait for indexing after each batch")
    p.add_argument("--poll-interval", type=int, default=3, help="Polling interval in seconds")
    p.add_argument("--start-row", type=int, default=1, help="Only ingest CSV rows >= this number (1-based)")
    p.add_argument("--end-row", type=int, default=None, help="Only ingest CSV rows <= this number (1-based)")
    p.add_argument("--max-batches", type=int, default=None, help="Optional limit on number of upload batches")
    p.add_argument("--retry-wait", type=int, default=5, help="Seconds to wait before retrying a failed upload")
    args = p.parse_args()

    csv_path = Path(args.csv_path).expanduser().resolve()
    if not csv_path.exists():
        print(f"CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    documents = build_documents(csv_path, None, None)
    if args.start_row > 1:
        documents = [d for d in documents if d["row"] >= args.start_row]
    if args.end_row is not None:
        documents = [d for d in documents if d["row"] <= args.end_row]

    total = len(documents)
    print(f"Vector store ID: {args.resume_store_id}")
    print(f"Rows to ingest: {total}")

    _, completed, _, _, _ = get_file_counts(args.endpoint, args.resume_store_id)
    done_rows = set(range(1, completed + 1)) if completed else set()
    pending = [d for d in documents if d["row"] not in done_rows]
    print(f"Resume: store has {completed} completed files; {len(pending)} rows pending")

    sent_batches = 0
    uploaded = completed

    for batch_start in range(0, len(pending), args.batch_size):
        if args.max_batches is not None and sent_batches >= args.max_batches:
            break

        batch = pending[batch_start : batch_start + args.batch_size]
        first_row = batch[0]["row"]
        last_row = batch[-1]["row"]
        print(f"Uploading rows {first_row}..{last_row} ({len(batch)} files)")

        for doc in batch:
            while True:
                try:
                    file_id = multipart_upload(args.endpoint, doc["filename"], doc["content"])
                    status, attach_resp = attach_file(
                        args.endpoint, args.resume_store_id, file_id, args.chunk_size
                    )
                    print(
                        f"  row {doc['row']}: file_id={file_id} attach_status={status} "
                        f"status={attach_resp.get('status', 'unknown')}"
                    )
                    break
                except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
                    if isinstance(e, urllib.error.HTTPError):
                        body = e.read().decode()
                        print(f"HTTP error {e.code} on row {doc['row']}: {body[:500]}", file=sys.stderr)
                        if e.code in (404, 405):
                            sys.exit(1)
                    else:
                        print(f"Request error on row {doc['row']}: {e}", file=sys.stderr)
                    print(f"Retrying row {doc['row']} in {args.retry_wait}s...", file=sys.stderr)
                    time.sleep(args.retry_wait)

        target_completed = uploaded + len(batch)
        uploaded = wait_for_progress(
            args.endpoint,
            args.resume_store_id,
            target_completed=target_completed,
            wait_seconds=args.wait_seconds,
            poll_interval=args.poll_interval,
        )
        sent_batches += 1
        print(f"Checkpoint: store completed={uploaded}/{total}")

        if uploaded >= total:
            break

    final_counts, final_completed, _, final_failed, _ = get_file_counts(args.endpoint, args.resume_store_id)
    print("\nFinal success summary:")
    print(f"Vector store ID: {args.resume_store_id}")
    print(f"Store file counts: {json.dumps(final_counts)}")
    print(f"Completed files: {final_completed}/{total} failed={final_failed}")
    if final_completed >= total and final_failed == 0:
        print("Result: ALL ROWS INDEXED")
    else:
        print(f"Result: PARTIAL ({max(0, total - final_completed)} remaining or failed)")


if __name__ == "__main__":
    main()
