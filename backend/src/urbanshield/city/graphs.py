"""Reachability and dependency graphs as sparse matrices, plus BFS tools. Owner: A.

Agents call ``bfs_reach`` and ``blast_radius`` as tools. Keep them fast and pure.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

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
    raise NotImplementedError


def bfs_reach(graphs: CityGraphs, sources: Iterable[str], blocked: Iterable[str] = ()) -> set[str]:
    """Devices an attacker can reach from ``sources`` over REACH edges, never entering
    ``blocked``. Sources are included in the result unless blocked."""
    raise NotImplementedError


def blast_radius(graphs: CityGraphs, device_id: str) -> list[str]:
    """Devices whose service is lost if ``device_id`` is lost (DEPENDS closure),
    excluding the device itself, sorted by ID."""
    raise NotImplementedError


def reach_centrality(graphs: CityGraphs) -> dict[str, int]:
    """For each device, how many devices it can reach. Used by the BFS-only baseline."""
    raise NotImplementedError
