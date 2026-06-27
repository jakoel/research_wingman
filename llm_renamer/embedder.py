"""
Phase 5 — Local embedding + FAISS vector index.

Embeds function summaries via Ollama and stores them in a FAISS flat cosine-
similarity index so Phase 6 can answer free-text queries like
"user-controlled length without bounds check".

Requires: pip install faiss-cpu numpy
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


try:
    import numpy as np
    import faiss as _faiss
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

    def __init__(self, config: dict) -> None:
        _require()
        self._url = config["ollama"]["url"].rstrip("/")
        self._model = config.get("kb", {}).get("embed_model", "nomic-embed-text")
        self._timeout = int(config["ollama"].get("timeout_seconds", 120))
        self._index_path = config.get("kb", {}).get("faiss_file", "kb_vectors.faiss")
        self._map_path = self._index_path + ".map"
        self._index = None
        self._id_map: list[str] = []

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_index(self, entries: list[dict]) -> None:
        """Embed all KB entries with a summary and build a fresh FAISS index."""
        import numpy as np
        import faiss

        vectors: list[list[float]] = []
        addresses: list[str] = []
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
            except Exception as e:
                print(f"[embedder] WARNING: embed failed for {entry['address']}: {e}")
            if (i + 1) % 100 == 0 or (i + 1) == total:
                print(f"[embedder] Embedded {i + 1}/{total}…")

        if not vectors:
            print("[embedder] No vectors produced — index not built.")
            return

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
        import faiss
        faiss.write_index(self._index, self._index_path)
        with open(self._map_path, "w", encoding="utf-8") as f:
            json.dump(self._id_map, f)

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
