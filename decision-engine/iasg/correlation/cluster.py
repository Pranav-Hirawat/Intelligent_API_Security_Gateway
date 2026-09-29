"""
Union-find clustering.

Two IPs are linked when they share enough traits. Union-find then turns those
pairwise links into groups: if A links to B and B links to C, all three end up
in one campaign even though A and C were never compared directly.
"""

from __future__ import annotations

from iasg.correlation.features import IPProfile, shared_traits


class UnionFind:
    """Tracks which items belong to the same group."""

    def __init__(self, items: list[str]) -> None:
        self._parent = {item: item for item in items}

    def find(self, item: str) -> str:
        """The group leader for this item."""
        root = item
        while self._parent[root] != root:
            root = self._parent[root]

        # Path compression: point everything straight at the root so the next
        # lookup is instant.
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        """Merge two groups."""
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a

    def groups(self) -> list[list[str]]:
        out: dict[str, list[str]] = {}
        for item in self._parent:
            out.setdefault(self.find(item), []).append(item)
        return [sorted(members) for members in out.values()]


def cluster(
    profiles: dict[str, IPProfile],
    min_shared: int = 2,
    window_seconds: int = 300,
) -> list[tuple[list[str], list[str]]]:
    """
    Group IPs into campaigns.

    Returns (ips, traits) pairs, where traits are the links that held the
    group together. Comparison is pairwise, which is fine at the scale a
    single gateway produces.
    """
    ips = sorted(profiles)
    uf = UnionFind(ips)
    traits_seen: dict[str, set[str]] = {ip: set() for ip in ips}

    for i, a in enumerate(ips):
        for b in ips[i + 1 :]:
            traits = shared_traits(profiles[a], profiles[b], window_seconds)

            # Two gates beyond the count:
            #
            # Timing is required. Two IPs with an identical fingerprint a day
            # apart are two incidents, not one coordinated campaign. Slow
            # campaigns still accumulate, because each cycle's cluster merges
            # into the stored campaign by IP overlap.
            #
            # At least two IDENTITY traits are required. "Same attack type at
            # the same time" describes every busy minute on a public API and
            # would sweep unrelated traffic into one campaign.
            identity = sum(t in ("user_agent", "endpoint", "subnet") for t in traits)
            if "timing" in traits and identity >= 2 and len(traits) >= min_shared:
                uf.union(a, b)
                traits_seen[a].update(traits)
                traits_seen[b].update(traits)

    clusters = []
    for members in uf.groups():
        traits = set()
        for ip in members:
            traits.update(traits_seen[ip])
        clusters.append((members, sorted(traits)))
    return clusters
