"""
Alert correlation service.

Entry point
-----------
    correlate_alerts(alerts: list[Alert]) -> list[Incident]

Algorithm
---------
1. Build an inverted index that maps each observable field value
   (host, user, source_ip, destination_ip, ioc) to the alert IDs that
   share it.  This is the "blocking" step that avoids an O(n²) scan.

2. For each candidate pair produced by the index, check that both alerts
   fall within MAX_WINDOW_MINUTES of each other.  Only then compute the
   full weighted correlation score.

3. If the score is >= CORRELATION_THRESHOLD, add a correlation edge
   between the two alerts.

4. Run Union-Find over all edges to build connected components.
   Every alert — even one with no edges — belongs to exactly one
   component (its own single-alert incident).

5. Convert each component to an Incident object with chronologically
   ordered alert_ids and mean edge score.

Tuning constants
----------------
    CORRELATION_THRESHOLD  float   minimum score to create an edge
    MAX_WINDOW_MINUTES     int     maximum minutes between two alerts
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from app.models.alert import Alert
from app.models.incident import CorrelationEdge, Incident

# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

CORRELATION_THRESHOLD: float = 0.40
MAX_WINDOW_MINUTES: int = 30

# Signal weights (must sum to 1.0)
_W_HOST        = 0.30
_W_USER        = 0.20
_W_SRC_IP      = 0.15
_W_DST_IP      = 0.10
_W_IOC         = 0.10
_W_TIME        = 0.10
_W_TECHNIQUE   = 0.05


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_value(v: str | None) -> bool:
    """Return True if a field value is non-null and non-empty."""
    return bool(v and v.strip())


def _time_proximity(a: Alert, b: Alert) -> float:
    """
    Return a score in [0, 1] reflecting how close the timestamps are.

    Score is 1.0 when the gap is 0 minutes and decays linearly to 0.0
    at MAX_WINDOW_MINUTES.  Alerts beyond the window are never passed
    to this function, but we clamp defensively.
    """
    gap_seconds = abs((a.timestamp - b.timestamp).total_seconds())
    gap_minutes = gap_seconds / 60.0
    if gap_minutes >= MAX_WINDOW_MINUTES:
        return 0.0
    return 1.0 - (gap_minutes / MAX_WINDOW_MINUTES)


def _compute_score(a: Alert, b: Alert) -> tuple[float, list[str]]:
    """
    Compute the weighted correlation score between two alerts.

    Returns
    -------
    score   : float       weighted sum in [0, 1]
    signals : list[str]   names of the signals that contributed non-zero weight
    """
    score = 0.0
    signals: list[str] = []

    # host
    if _has_value(a.host) and a.host == b.host:
        score += _W_HOST
        signals.append("host")

    # user
    if _has_value(a.user) and a.user == b.user:
        score += _W_USER
        signals.append("user")

    # source_ip
    if _has_value(a.source_ip) and a.source_ip == b.source_ip:
        score += _W_SRC_IP
        signals.append("source_ip")

    # destination_ip
    if _has_value(a.destination_ip) and a.destination_ip == b.destination_ip:
        score += _W_DST_IP
        signals.append("destination_ip")

    # ioc
    if _has_value(a.ioc) and a.ioc == b.ioc:
        score += _W_IOC
        signals.append("ioc")

    # time proximity (always computed, always contributes)
    tp = _time_proximity(a, b)
    score += _W_TIME * tp
    if tp > 0:
        signals.append("time")

    # mitre technique (same top-level technique prefix is enough)
    if _has_value(a.mitre_technique) and _has_value(b.mitre_technique):
        ta = a.mitre_technique.split(".")[0]   # type: ignore[union-attr]
        tb = b.mitre_technique.split(".")[0]   # type: ignore[union-attr]
        if ta == tb:
            score += _W_TECHNIQUE
            signals.append("technique")

    return round(score, 6), signals


def _within_window(a: Alert, b: Alert) -> bool:
    gap = abs((a.timestamp - b.timestamp).total_seconds())
    return gap <= MAX_WINDOW_MINUTES * 60


# ---------------------------------------------------------------------------
# Inverted-index candidate generation
# ---------------------------------------------------------------------------

def _build_candidate_pairs(alerts: list[Alert]) -> set[tuple[int, int]]:
    """
    Build a set of (i, j) index pairs — with i < j — that share at least
    one observable field value.  This avoids comparing all O(n²) pairs.
    """
    # Map each (field_name, value) -> list of alert indices
    buckets: dict[tuple[str, str], list[int]] = defaultdict(list)

    for idx, alert in enumerate(alerts):
        if _has_value(alert.host):
            buckets[("host", alert.host)].append(idx)          # type: ignore[arg-type]
        if _has_value(alert.user):
            buckets[("user", alert.user)].append(idx)          # type: ignore[arg-type]
        if _has_value(alert.source_ip):
            buckets[("src_ip", alert.source_ip)].append(idx)   # type: ignore[arg-type]
        if _has_value(alert.destination_ip):
            buckets[("dst_ip", alert.destination_ip)].append(idx)  # type: ignore[arg-type]
        if _has_value(alert.ioc):
            buckets[("ioc", alert.ioc)].append(idx)            # type: ignore[arg-type]

    pairs: set[tuple[int, int]] = set()
    for indices in buckets.values():
        for x in range(len(indices)):
            for y in range(x + 1, len(indices)):
                i, j = indices[x], indices[y]
                pairs.add((min(i, j), max(i, j)))

    return pairs


# ---------------------------------------------------------------------------
# Union-Find
# ---------------------------------------------------------------------------

class _UnionFind:
    def __init__(self, n: int) -> None:
        self._parent = list(range(n))
        self._rank   = [0] * n

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]  # path compression
            x = self._parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate_alerts(alerts: list[Alert]) -> list[Incident]:
    """
    Group a list of normalized Alert objects into Incident objects.

    Parameters
    ----------
    alerts : list[Alert]
        Normalized alerts (may be empty).

    Returns
    -------
    list[Incident]
        One Incident per connected component, sorted by start_time.
        Single-alert incidents are included (no edge, score = 0.0).
    """
    if not alerts:
        return []

    # Index alerts by id for quick look-up
    by_id: dict[str, Alert] = {a.alert_id: a for a in alerts}

    # --- 1. Candidate pairs via inverted index ---
    candidate_pairs = _build_candidate_pairs(alerts)

    # --- 2. Score candidates; keep edges above threshold ---
    edges: list[CorrelationEdge] = []
    uf = _UnionFind(len(alerts))

    for i, j in candidate_pairs:
        a, b = alerts[i], alerts[j]

        if not _within_window(a, b):
            continue

        score, signals = _compute_score(a, b)
        if score >= CORRELATION_THRESHOLD:
            edges.append(CorrelationEdge(
                alert_a=a.alert_id,
                alert_b=b.alert_id,
                score=score,
                signals=signals,
            ))
            uf.union(i, j)

    # --- 3. Build connected components ---
    components: dict[int, list[int]] = defaultdict(list)
    for idx in range(len(alerts)):
        components[uf.find(idx)].append(idx)

    # --- 4. Build edge look-up per component root ---
    # Map alert_id -> component root index
    alert_root: dict[str, int] = {}
    for root, members in components.items():
        for idx in members:
            alert_root[alerts[idx].alert_id] = root

    component_edges: dict[int, list[CorrelationEdge]] = defaultdict(list)
    for edge in edges:
        root = alert_root[edge.alert_a]
        component_edges[root].append(edge)

    # --- 5. Create Incident objects ---
    incidents: list[Incident] = []

    for incident_seq, (root, member_indices) in enumerate(
        sorted(components.items()), start=1
    ):
        member_alerts = sorted(
            [alerts[idx] for idx in member_indices],
            key=lambda a: a.timestamp,
        )
        alert_ids = [a.alert_id for a in member_alerts]
        start_time = member_alerts[0].timestamp
        end_time   = member_alerts[-1].timestamp

        c_edges = component_edges[root]
        corr_score = (
            round(sum(e.score for e in c_edges) / len(c_edges), 6)
            if c_edges else 0.0
        )

        incidents.append(Incident(
            incident_id=f"INC-{incident_seq:03d}",
            alert_ids=alert_ids,
            start_time=start_time,
            end_time=end_time,
            correlation_score=corr_score,
            correlation_evidence=c_edges,
        ))

    # --- 6. Sort incidents by start_time ---
    incidents.sort(key=lambda inc: inc.start_time)

    # Re-assign sequential IDs after sorting
    for seq, inc in enumerate(incidents, start=1):
        inc.incident_id = f"INC-{seq:03d}"

    return incidents
