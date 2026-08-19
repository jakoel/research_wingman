"""
Local embedding + FAISS vector index.

Embeds function summaries via Ollama into a FAISS flat cosine-similarity index
so `research_wingman.py ask` can answer free-text questions like "user-controlled length without
bounds check". The index is rebuilt automatically when it falls behind the
knowledge base.

Requires: pip install faiss-cpu numpy
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request


try:
    import numpy as np
    import faiss
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class EmbedderUnavailable(Exception):
    pass


def _require() -> None:
    if not _AVAILABLE:
        raise EmbedderUnavailable(
            "faiss-cpu and numpy are required for Phase 5/6.\n"
            "Install with:  pip install faiss-cpu numpy"
        )


class Embedder:
    """
    Wraps a FAISS IndexFlatIP index with an address-to-ID map.

    Files on disk:
      <faiss_file>       — FAISS binary index
      <faiss_file>.map   — JSON list of function addresses (FAISS row -> address)
    """

    def __init__(self, config: dict, index_path: str) -> None:
        _require()
        self._url = config["ollama"]["url"].rstrip("/")
        self._model = config["ollama"].get("embed_model", "nomic-embed-text")
        self._timeout = int(config["ollama"].get("timeout_seconds", 120))
        self._index_path = index_path
        self._map_path = index_path + ".map"
        self._sig_path = index_path + ".sig"
        self._index = None
        self._id_map: list[str] = []
        self._signature: str | None = None

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_index(self, entries: list[dict]) -> None:
        """Embed all KB entries with a summary and build a fresh FAISS index."""
        import numpy as np
        import faiss

        vectors: list[list[float]] = []
        addresses: list[str] = []
        embedded_entries: list[dict] = []
        total = len(entries)

        for i, entry in enumerate(entries):
            summary = entry.get("summary") or ""
            if not summary:
                continue
            text = _entry_to_text(entry)
            try:
                vec = self._embed(text)
                vectors.append(vec)
                addresses.append(str(entry["address"]))
                embedded_entries.append(entry)
            except Exception as e:
                print(f"[embedder] WARNING: embed failed for {entry['address']}: {e}")
            if (i + 1) % 100 == 0 or (i + 1) == total:
                print(f"[embedder] Embedded {i + 1}/{total}…")

        if not vectors:
            print("[embedder] No vectors produced — index not built.")
            return

        # Signature computed from what actually made it into the index, not
        # the full input list -- if some embed calls failed above (e.g. a
        # transient network error), a signature over the full input would
        # match on the next run's unchanged KB rows even though the failed
        # entries are still permanently missing, so the index would look
        # "fresh" and never get a chance to retry them (short of deleting
        # the .faiss files by hand). Confirmed real gap 2026-08-16.
        self._signature = self.content_signature(embedded_entries)

        matrix = np.array(vectors, dtype=np.float32)
        faiss.normalize_L2(matrix)

        dim = matrix.shape[1]
        index = faiss.IndexFlatIP(dim)  # inner product on L2-normalised = cosine sim
        index.add(matrix)

        self._index = index
        self._id_map = addresses
        self._save()
        print(
            f"[embedder] Index built: {len(addresses)} vectors, "
            f"dim={dim}, saved to {self._index_path}"
        )

    # ------------------------------------------------------------------
    # Persist / load
    # ------------------------------------------------------------------

    def _save(self) -> None:
        # Atomic: write every file to a .tmp path, then rename into place
        # only after ALL writes succeed -- same pattern as CallGraph.save().
        # A crash/interrupt mid-save previously could leave a written
        # .faiss index paired with a stale or missing .map, desyncing FAISS
        # row positions from the address list search() trusts 1:1.
        # Confirmed real risk 2026-08-16 (only on crash/interrupt, not
        # normal control flow).
        import faiss
        index_tmp = self._index_path + ".tmp"
        map_tmp = self._map_path + ".tmp"
        faiss.write_index(self._index, index_tmp)
        with open(map_tmp, "w", encoding="utf-8") as f:
            json.dump(self._id_map, f)
        if self._signature is not None:
            sig_tmp = self._sig_path + ".tmp"
            with open(sig_tmp, "w", encoding="utf-8") as f:
                f.write(self._signature)
            os.replace(sig_tmp, self._sig_path)
        os.replace(index_tmp, self._index_path)
        os.replace(map_tmp, self._map_path)

    # ------------------------------------------------------------------
    # Content signature — freshness that tracks *content*, not just count
    # ------------------------------------------------------------------

    @staticmethod
    def content_signature(entries: list[dict]) -> str:
        """
        A hash of exactly what would be embedded — the (address, embed-text)
        of every entry with a summary, sorted by address. Any add, edit
        (refinement / --redo changing a summary), or removal changes this,
        so freshness catches content changes a plain count comparison misses.
        """
        items = sorted(
            (str(e["address"]), _entry_to_text(e))
            for e in entries if (e.get("summary") or "")
        )
        h = hashlib.sha1()
        for addr, text in items:
            h.update(addr.encode("utf-8"))
            h.update(b"\x00")
            h.update(text.encode("utf-8"))
            h.update(b"\x01")
        return h.hexdigest()

    def stored_signature(self) -> str | None:
        try:
            with open(self._sig_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None

    def load(self) -> bool:
        """Load index from disk. Returns True on success."""
        import faiss
        if not os.path.exists(self._index_path) or not os.path.exists(self._map_path):
            return False
        try:
            self._index = faiss.read_index(self._index_path)
            with open(self._map_path, "r", encoding="utf-8") as f:
                self._id_map = json.load(f)
            return True
        except Exception as e:
            print(f"[embedder] Failed to load index: {e}")
            return False

    def is_ready(self) -> bool:
        return self._index is not None and bool(self._id_map)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, query: str, top_k: int = 20) -> list[tuple[str, float]]:
        """
        Return (address_str, cosine_similarity) pairs for the top_k matches.
        """
        if not self.is_ready():
            raise EmbedderUnavailable("Index not built or loaded.")
        import numpy as np
        import faiss

        vec = np.array([self._embed(query)], dtype=np.float32)
        faiss.normalize_L2(vec)
        k = min(top_k, len(self._id_map))
        distances, indices = self._index.search(vec, k)

        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if 0 <= idx < len(self._id_map):
                results.append((self._id_map[int(idx)], float(dist)))
        return results

    # ------------------------------------------------------------------
    # Embedding calls (Ollama)
    # ------------------------------------------------------------------

    def _embed(self, text: str) -> list[float]:
        """Try /api/embed (Ollama 0.3+); fall back to /api/embeddings."""
        try:
            return self._call_embed_endpoint(text)
        except (urllib.error.URLError, EmbedderUnavailable):
            return self._call_embeddings_endpoint(text)

    def _call_embed_endpoint(self, text: str) -> list[float]:
        payload = json.dumps({"model": self._model, "input": text}).encode()
        req = urllib.request.Request(
            f"{self._url}/api/embed",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read())
        if "embeddings" in data and data["embeddings"]:
            return data["embeddings"][0]
        if "embedding" in data:
            return data["embedding"]
        raise EmbedderUnavailable(f"Unexpected /api/embed response: {list(data)}")

    def _call_embeddings_endpoint(self, text: str) -> list[float]:
        payload = json.dumps({"model": self._model, "prompt": text}).encode()
        req = urllib.request.Request(
            f"{self._url}/api/embeddings",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read())
        if "embedding" in data:
            return data["embedding"]
        raise EmbedderUnavailable(
            f"Unexpected /api/embeddings response: {list(data)}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_to_text(entry: dict) -> str:
    """Build a text representation of a KB entry suitable for embedding."""
    parts = []
    name = entry.get("new_name") or entry.get("old_name") or ""
    if name:
        parts.append(f"Function: {name}")
    summary = entry.get("summary") or ""
    if summary:
        parts.append(f"Summary: {summary}")
    behaviors = entry.get("interesting_behaviors") or []
    if behaviors:
        parts.append("Behaviors: " + "; ".join(str(b) for b in behaviors))
    return " | ".join(parts) if parts else name
