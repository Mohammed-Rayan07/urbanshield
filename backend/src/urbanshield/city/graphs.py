"""Reachability and dependency graphs as sparse matrices, plus BFS tools. Owner: A.

Agents call ``bfs_reach`` and ``blast_radius`` as tools. Keep them fast and pure.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np
import scipy.sparse as sp

from urbanshield.schemas import City


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
    reach_rows: list[int] = []
    reach_cols: list[int] = []
    depends_rows: list[int] = []
    depends_cols: list[int] = []

    for edge in city.edges:
        src = index[edge.src]
        dst = index[edge.dst]
        if edge.kind.value == "reach":
            reach_rows.append(src)
            reach_cols.append(dst)
        elif edge.kind.value == "depends":
            depends_rows.append(src)
            depends_cols.append(dst)

    shape = (len(device_ids), len(device_ids))
    reach = sp.csr_matrix(
        (np.ones(len(reach_rows), dtype=np.int8), (reach_rows, reach_cols)),
        shape=shape,
        dtype=np.int8,
    )
    depends = sp.csr_matrix(
        (np.ones(len(depends_rows), dtype=np.int8), (depends_rows, depends_cols)),
        shape=shape,
        dtype=np.int8,
    )
    return CityGraphs(device_ids=device_ids, index=index, reach=reach, depends=depends)


def bfs_reach(graphs: CityGraphs, sources: Iterable[str], blocked: Iterable[str] = ()) -> set[str]:
    """Devices an attacker can reach from ``sources`` over REACH edges, never entering
    ``blocked``. Sources are included in the result unless blocked."""
    blocked_ids = set(blocked)
    visited = np.zeros(len(graphs.device_ids), dtype=bool)
    frontier: list[int] = []

    for source in sources:
        position = graphs.index.get(source)
        if position is None or source in blocked_ids or visited[position]:
            continue
        visited[position] = True
        frontier.append(position)

    while frontier:
        next_frontier: list[int] = []
        for source_position in frontier:
            start, end = graphs.reach.indptr[source_position : source_position + 2]
            for target_position in graphs.reach.indices[start:end]:
                target_id = graphs.device_ids[target_position]
                if target_id in blocked_ids or visited[target_position]:
                    continue
                visited[target_position] = True
                next_frontier.append(int(target_position))
        frontier = next_frontier

    return {device_id for position, device_id in enumerate(graphs.device_ids) if visited[position]}


def blast_radius(graphs: CityGraphs, device_id: str) -> list[str]:
    """Devices whose service is lost if ``device_id`` is lost (DEPENDS closure),
    excluding the device itself, sorted by ID."""
    source = graphs.index[device_id]
    visited = np.zeros(len(graphs.device_ids), dtype=bool)
    visited[source] = True
    frontier = [source]

    while frontier:
        next_frontier: list[int] = []
        for current in frontier:
            start, end = graphs.depends.indptr[current : current + 2]
            for target in graphs.depends.indices[start:end]:
                if visited[target]:
                    continue
                visited[target] = True
                next_frontier.append(int(target))
        frontier = next_frontier

    return sorted(
        graphs.device_ids[position]
        for position, is_reached in enumerate(visited)
        if is_reached and position != source
    )


def reach_centrality(graphs: CityGraphs) -> dict[str, int]:
    """For each device, how many devices it can reach. Used by the BFS-only baseline."""
    return {device_id: len(bfs_reach(graphs, [device_id])) - 1 for device_id in graphs.device_ids}
