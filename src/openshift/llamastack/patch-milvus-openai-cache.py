#!/usr/bin/env python3
"""Patch Llama Stack Milvus provider for OpenAI vector store cache restore.

Stock llama-stack (tested through 0.3.2) calls initialize_openai_vector_stores()
on startup but does not register those stores in the Milvus in-memory cache used
by knowledge_search / RAG. After a Llama Stack restart you may see:

  Vector Store not found

This script patches site-packages:
  llama_stack/providers/remote/vector_io/milvus/milvus.py

Upstream context:
  - https://github.com/llamastack/llama-stack/pull/3977 (partial fix)
  - https://github.com/llamastack/llama-stack/issues/5209 (restart persistence)

Safe to re-run: exits 0 if the patch is already applied.
Re-apply after: pip install --upgrade llama-stack
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

PATCH_MARKER = 'agentic-patching: openai-milvus-cache-restore'

INIT_OLD = """        # Load existing OpenAI vector stores into the in-memory cache
        await self.initialize_openai_vector_stores()

    async def shutdown(self) -> None:"""

INIT_NEW = f"""        # Load existing OpenAI vector stores into the in-memory cache
        await self.initialize_openai_vector_stores()
        # {PATCH_MARKER}
        for store_id, store_info in self.openai_vector_stores.items():
            if store_id in self.cache:
                continue
            meta = store_info.get("metadata") or {{}}
            vector_store = VectorStore(
                identifier=store_id,
                embedding_dimension=int(meta.get("embedding_dimension", 768)),
                embedding_model=meta.get("embedding_model") or "sentence-transformers/nomic-ai/nomic-embed-text-v1.5",
                provider_id=meta.get("provider_id", "milvus"),
                provider_resource_id=store_id,
                vector_store_name=store_info.get("name"),
            )
            await self.register_vector_store(vector_store)

    async def _register_openai_vector_store_if_needed(self, vector_store_id: str) -> VectorStoreWithIndex | None:
        store_info = self.openai_vector_stores.get(vector_store_id)
        if not store_info:
            return None
        meta = store_info.get("metadata") or {{}}
        vector_store = VectorStore(
            identifier=vector_store_id,
            embedding_dimension=int(meta.get("embedding_dimension", 768)),
            embedding_model=meta.get("embedding_model") or "sentence-transformers/nomic-ai/nomic-embed-text-v1.5",
            provider_id=meta.get("provider_id", "milvus"),
            provider_resource_id=vector_store_id,
            vector_store_name=store_info.get("name"),
        )
        await self.register_vector_store(vector_store)
        return self.cache.get(vector_store_id)

    async def shutdown(self) -> None:"""

CACHE_OLD_03 = """        if self.vector_store_table is None:
            raise VectorStoreNotFoundError(vector_store_id)"""

CACHE_OLD_07 = """        if not vector_store_data:
            raise VectorStoreNotFoundError(vector_store_id)"""

CACHE_NEW = f"""        if not vector_store_data:
            # {PATCH_MARKER}
            index = await self._register_openai_vector_store_if_needed(vector_store_id)
            if index:
                return index
            raise VectorStoreNotFoundError(vector_store_id)"""

CACHE_NEW_03 = f"""        if self.vector_store_table is None:
            # {PATCH_MARKER}
            index = await self._register_openai_vector_store_if_needed(vector_store_id)
            if index:
                return index
            raise VectorStoreNotFoundError(vector_store_id)"""


def find_milvus_py(explicit: str | None = None) -> Path:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f'milvus.py not found: {path}')
        return path
    spec = importlib.util.find_spec('llama_stack')
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError('llama_stack is not installed; run: pip install llama-stack')
    base = Path(next(iter(spec.submodule_search_locations)))
    path = base / 'providers' / 'remote' / 'vector_io' / 'milvus' / 'milvus.py'
    if not path.is_file():
        raise FileNotFoundError(f'Expected Milvus provider at: {path}')
    return path


def patch_is_applied(text: str) -> bool:
    return (
        '_register_openai_vector_store_if_needed' in text
        and 'index = await self._register_openai_vector_store_if_needed(vector_store_id)' in text
    )


def apply_patch(text: str) -> str:
    if patch_is_applied(text):
        return text
    if INIT_OLD not in text:
        raise RuntimeError(
            'initialize() block did not match expected llama-stack source; '
            'llama-stack version may have changed — update this script.'
        )
    text = text.replace(INIT_OLD, INIT_NEW, 1)
    if CACHE_OLD_07 in text:
        return text.replace(CACHE_OLD_07, CACHE_NEW, 1)
    if CACHE_OLD_03 in text:
        return text.replace(CACHE_OLD_03, CACHE_NEW_03, 1)
    raise RuntimeError(
        '_get_and_cache_vector_store_index() block did not match expected source; '
        'llama-stack version may have changed — update this script.'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--milvus-py', help='Optional path to milvus.py (default: installed llama_stack package)')
    parser.add_argument('--check', action='store_true', help='Exit 0 if patch applied, 1 if not')
    parser.add_argument('--dry-run', action='store_true', help='Print actions without writing')
    args = parser.parse_args()

    path = find_milvus_py(args.milvus_py)
    original = path.read_text()
    if patch_is_applied(original):
        print(f'OK: patch already applied in {path}')
        return 0
    if args.check:
        print(f'PATCH NEEDED: {path}')
        return 1

    updated = apply_patch(original)
    if args.dry_run:
        print(f'Would patch: {path}')
        return 0

    path.write_text(updated)
    print(f'Patched: {path}')
    print('Restart Llama Stack so the Milvus provider reloads with the fix.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        raise SystemExit(1)
