#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4


def http_json(method: str, url: str, payload=None, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req) as r:
        body = r.read().decode()
        return r.status, json.loads(body) if body else None


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
            metadata = {
                "source": str(csv_path),
                "row": i,
            }
            if "display_name" in row and row.get("display_name"):
                metadata["display_name"] = row.get("display_name")

            docs.append(
                {
                    "document_id": str(doc_id),
                    "content": content,
                    "mime_type": "text/plain",
                    "metadata": metadata,
                }
            )
    return docs


def chunked(items, size):
    for i in range(0, len(items), size):
        yield i, items[i:i + size]


def get_file_counts(endpoint: str, vector_store_id: str):
    _, store = http_json("GET", f"{endpoint}/v1/vector_stores/{vector_store_id}")
    file_counts = store.get("file_counts", {})
    counts = {
        key: value
        for key, value in file_counts.items()
        if key != "total" and value
    }
    completed = int(file_counts.get("completed", 0) or 0)
    # Rows are ingested sequentially; use completed file count as resume checkpoint.
    rows = set(range(1, completed + 1)) if completed else set()
    return counts, rows, store


def wait_for_progress(endpoint: str, vector_store_id: str, known_done_rows: set[int], wait_seconds: int, poll_interval: int):
    """
    Wait only until some progress is made, not until the whole submitted batch completes.
    """
    deadline = time.time() + wait_seconds
    last_count = len(known_done_rows)

    while time.time() < deadline:
        counts, rows, files = get_file_counts(endpoint, vector_store_id)
        new_done = len(rows - known_done_rows)
        print(f"Statuses: {counts} | new_rows_indexed={new_done} | total_indexed={len(rows)}")

        if len(rows) > last_count:
            return counts, rows, files

        time.sleep(poll_interval)

    return get_file_counts(endpoint, vector_store_id)


def print_checkpoint(done_rows: set[int], total_docs: int, counts: dict, batch_no: int | None = None):
    prefix = f"Checkpoint after batch {batch_no}:" if batch_no is not None else "Checkpoint:"
    print(f"{prefix} indexed_rows={len(done_rows)}/{total_docs} status_counts={json.dumps(counts)}")


def main():
    p = argparse.ArgumentParser(description="Create a Llama Stack vector store and ingest a CSV into RAG")
    p.add_argument("csv_path", help="Path to CSV file")
    p.add_argument("--endpoint", default="http://127.0.0.1:8321", help="Llama Stack endpoint")
    p.add_argument("--store-name", default=None, help="Vector store name (default: csv filename + random suffix)")
    p.add_argument("--id-column", default=None, help="CSV column to use as document_id")
    p.add_argument("--text-columns", default=None, help="Comma-separated CSV columns to include in content. Default: all columns")
    p.add_argument("--chunk-size", type=int, default=256, help="Chunk size in tokens")
    p.add_argument("--wait-seconds", type=int, default=30, help="How long to wait for progress after each batch")
    p.add_argument("--poll-interval", type=int, default=3, help="Polling interval in seconds")
    p.add_argument("--batch-size", type=int, default=20, help="How many rows/documents to insert per request")
    p.add_argument("--resume-store-id", default=None, help="Resume ingestion into an existing vector store id")
    p.add_argument("--start-row", type=int, default=1, help="Only ingest CSV rows >= this number (1-based)")
    p.add_argument("--end-row", type=int, default=None, help="Only ingest CSV rows <= this number (1-based)")
    p.add_argument("--max-batches", type=int, default=None, help="Optional limit on number of batches to send")
    p.add_argument("--until-complete", action="store_true", help="Keep batching until all CSV rows are indexed")
    p.add_argument(
        "--query",
        default="Which host names are present in the uploaded CSV? Mention bastion if found.",
        help="Verification query to print and optionally run at the end",
    )
    p.add_argument("--run-query", action="store_true", help="Run the verification query automatically at the end")
    args = p.parse_args()

    csv_path = Path(args.csv_path).expanduser().resolve()
    if not csv_path.exists():
        print(f"CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    text_columns = [c.strip() for c in args.text_columns.split(",")] if args.text_columns else None

    if args.resume_store_id:
        vector_store_id = args.resume_store_id
        print(f"Resuming vector store ID: {vector_store_id}")
    else:
        store_name = args.store_name or f"{csv_path.stem}-{uuid4().hex[:8]}"
        _, store = http_json("POST", f"{args.endpoint}/v1/vector_stores", {"name": store_name})
        vector_store_id = store["id"]
        print(f"Created vector store: {store_name}")
        print(f"Vector store ID: {vector_store_id}")

    documents = build_documents(csv_path, args.id_column, text_columns)
    if args.start_row > 1:
        documents = [doc for doc in documents if doc["metadata"]["row"] >= args.start_row]
    if args.end_row is not None:
        documents = [doc for doc in documents if doc["metadata"]["row"] <= args.end_row]
    if args.start_row > 1 or args.end_row is not None:
        end_label = args.end_row if args.end_row is not None else "end"
        print(f"Ingesting CSV rows {args.start_row}-{end_label}: {len(documents)} documents")
    target_rows = {doc["metadata"]["row"] for doc in documents}
    total_docs = len(documents)

    counts, done_rows, _ = get_file_counts(args.endpoint, vector_store_id)
    completed = int(counts.get("completed", 0) or 0)
    if args.end_row is not None and args.start_row <= args.end_row:
        # Gap backfill: only track completion inside the requested row range.
        done_rows = set()
        print(f"Gap backfill mode: rows {args.start_row}-{args.end_row} | store has {completed} files total")
    elif args.start_row > 1:
        ingested_after_start = max(0, completed - (args.start_row - 1))
        done_rows = set(range(args.start_row, args.start_row + ingested_after_start))
        print(f"Resume checkpoint: treating rows 1-{args.start_row - 1} as done; {len(done_rows)} rows indexed from row {args.start_row}")
    else:
        done_rows = set(range(1, completed + 1)) if completed else set()
    done_in_target = done_rows & target_rows
    print(f"Existing indexed rows in target: {len(done_in_target)}/{total_docs} | status counts: {counts}")

    submitted_rows = set(done_in_target)
    sent_batches = 0

    while len(done_in_target) < total_docs:
        progress_this_pass = False

        for start, batch in chunked(documents, args.batch_size):
            if args.max_batches is not None and sent_batches >= args.max_batches:
                break

            pending = [doc for doc in batch if doc["metadata"]["row"] not in done_in_target and doc["metadata"]["row"] not in submitted_rows]
            if not pending:
                continue

            print(f"Sending batch rows {pending[0]['metadata']['row']}..{pending[-1]['metadata']['row']} | pending_docs={len(pending)}")
            payload = {
                "chunk_size_in_tokens": args.chunk_size,
                "documents": pending,
                "vector_store_id": vector_store_id,
            }

            status, _ = http_json(
                "POST",
                f"{args.endpoint}/v1/tool-runtime/rag-tool/insert",
                payload,
                extra_headers={"Accept": "*/*"},
            )
            print(f"Insert request status: {status}")

            for doc in pending:
                submitted_rows.add(doc["metadata"]["row"])

            old_done = set(done_in_target)
            counts, store_done_rows, _ = wait_for_progress(
                args.endpoint,
                vector_store_id,
                known_done_rows=done_rows,
                wait_seconds=args.wait_seconds,
                poll_interval=args.poll_interval,
            )
            done_rows = store_done_rows
            if args.end_row is not None and args.start_row <= args.end_row:
                done_in_target |= {doc["metadata"]["row"] for doc in pending}
            else:
                done_in_target = done_rows & target_rows

            if len(done_in_target) > len(old_done):
                progress_this_pass = True

            submitted_rows -= done_in_target

            sent_batches += 1
            print_checkpoint(done_in_target, total_docs, counts, sent_batches)

            if len(done_in_target) >= total_docs:
                break

        if len(done_in_target) >= total_docs:
            break

        if not args.until_complete:
            break

        if args.max_batches is not None and sent_batches >= args.max_batches:
            break

        if not progress_this_pass:
            print("No progress in this pass. Clearing submitted-but-not-completed tracking for retry.")
            submitted_rows = set(done_in_target)
            time.sleep(5)

    final_counts, final_rows, _ = get_file_counts(args.endpoint, vector_store_id)
    final_in_target = (final_rows & target_rows) if args.end_row is None else done_in_target
    print("\nFinal success summary:")
    print(f"Vector store ID: {vector_store_id}")
    print(f"Indexed rows in target: {len(final_in_target)} / {total_docs}")
    print(f"Store file counts: {json.dumps(final_counts)}")

    if len(final_in_target) == total_docs:
        print("Result: ALL ROWS INDEXED")
    else:
        print(f"Result: PARTIAL ({total_docs - len(final_in_target)} remaining in target range)")

    verify_payload = {"content": args.query, "vector_store_ids": [vector_store_id]}
    verify_cmd = (
        f"curl -sS {args.endpoint}/v1/tool-runtime/rag-tool/query "
        f"-H 'Content-Type: application/json' "
        f"-d '{json.dumps(verify_payload)}' | python3 -m json.tool"
    )
    print("\nVerification query command:")
    print(verify_cmd)

    if args.run_query:
        print("\nVerification query result:")
        _, result = http_json("POST", f"{args.endpoint}/v1/tool-runtime/rag-tool/query", verify_payload)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP error {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
