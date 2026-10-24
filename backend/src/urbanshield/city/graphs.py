"""Reachability and dependency graphs as sparse matrices, plus BFS tools. Owner: A.

Agents call ``bfs_reach`` and ``blast_radius`` as tools, and the BFS-only baseline calls
``reach_centrality`` on cities of up to 5,000 devices, so every traversal runs in
``scipy.sparse.csgraph`` (C), never a Python loop over edges.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np
import scipy.sparse as sp
from scipy.sparse import csgraph

from urbanshield.schemas import City, EdgeKind


@dataclass(frozen=True)
class CityGraphs:
    device_ids: tuple[str, ...]
    index: dict[str, int]
    reach: sp.csr_matrix  # (N, N) 1 where attacker can move i -> j
    depends: sp.csr_matrix  # (N, N) 1 where damage flows i -> j


def build_graphs(city: City) -> CityGraphs:
    """Index devices in ``city.devices`` order and build both adjacency matrices."""
    device_ids = tuple(device.id for device in city.devices)
    index = {device_id: position for position, device_id in enumerate(device_ids)}
    return CityGraphs(
        device_ids=device_ids,
        index=index,
        reach=_adjacency(city, index, EdgeKind.REACH),
        depends=_adjacency(city, index, EdgeKind.DEPENDS),
    )


def _adjacency(city: City, index: dict[str, int], kind: EdgeKind) -> sp.csr_matrix:
    n = len(index)
    pairs = np.array([(index[e.src], index[e.dst]) for e in city.edges if e.kind is kind], dtype=np.int64)
    if not len(pairs):
        return sp.csr_matrix((n, n), dtype=np.int8)
    adj = sp.csr_matrix((np.ones(len(pairs), dtype=np.int8), (pairs[:, 0], pairs[:, 1])), shape=(n, n))
    adj.data[:] = 1  # duplicate edges collapse to one
    return adj


def _positions(graphs: CityGraphs, device_ids: Iterable[str]) -> list[int]:
    ids = list(device_ids)
    unknown = sorted(set(ids) - graphs.index.keys())
    if unknown:
        raise KeyError(f"unknown device ids: {', '.join(unknown[:5])}")
    return [graphs.index[d] for d in ids]


def _reached(adj: sp.csr_matrix, starts: list[int]) -> np.ndarray:
    """Mask of nodes reachable from any of ``starts`` (inclusive): one C-level BFS from a
    virtual node wired to every start."""
    n = adj.shape[0]
    mask = np.zeros(n, dtype=bool)
    if not starts:
        return mask
    hub = sp.csr_matrix((np.ones(len(starts), dtype=np.int8), ([0] * len(starts), starts)), shape=(1, n))
    graph = sp.bmat([[adj, sp.csr_matrix((n, 1))], [hub, sp.csr_matrix((1, 1))]], format="csr")
    order = csgraph.breadth_first_order(graph, n, directed=True, return_predecessors=False)
    mask[order[order < n]] = True
    return mask


def bfs_reach(graphs: CityGraphs, sources: Iterable[str], blocked: Iterable[str] = ()) -> set[str]:
    """Devices an attacker can reach from ``sources`` over REACH edges, never entering
    ``blocked``. Sources are included in the result unless blocked. Unknown ids raise ``KeyError``."""
    starts = _positions(graphs, sources)
    blocked_positions = _positions(graphs, blocked)
    adj = graphs.reach
    if blocked_positions:
        keep = np.ones(adj.shape[0], dtype=np.int8)
        keep[blocked_positions] = 0
        mask = sp.diags(keep, dtype=np.int8)
        adj = (mask @ adj @ mask).tocsr()  # a blocked node neither receives nor passes on
        starts = [s for s in starts if keep[s]]
    return {graphs.device_ids[i] for i in np.flatnonzero(_reached(adj, starts))}


def blast_radius(graphs: CityGraphs, device_id: str) -> list[str]:
    """Devices whose service is lost if ``device_id`` is lost (DEPENDS closure),
    excluding the device itself, sorted by ID."""
    (source,) = _positions(graphs, [device_id])
    order = csgraph.breadth_first_order(graphs.depends, source, directed=True, return_predecessors=False)
    return sorted(graphs.device_ids[i] for i in order if i != source)


def reach_centrality(graphs: CityGraphs) -> dict[str, int]:
    """For each device, how many other devices it can reach. Used by the BFS-only baseline.

    Devices in the same strongly connected component reach exactly the same set, so one
    BFS per component suffices (field networks are bidirectional, so components are large).
    """
    _, labels = csgraph.connected_components(graphs.reach, directed=True, connection="strong")
    _, representatives = np.unique(labels, return_index=True)
    reach_size = np.array(
        [
            len(csgraph.breadth_first_order(graphs.reach, int(r), directed=True, return_predecessors=False))
            for r in representatives
        ]
    )
    return {
        device_id: int(reach_size[label]) - 1
        for device_id, label in zip(graphs.device_ids, labels, strict=True)
    }
