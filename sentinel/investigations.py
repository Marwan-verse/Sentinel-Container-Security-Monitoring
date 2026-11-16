"""Transactional configuration history and immutable incident evidence."""
import json
from datetime import datetime, timedelta

SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def configuration(item):
    # Runtime identities and IPs change on restart without a configuration change.
    details = {k: v for k, v in item.get("details", {}).items()
               if k not in {"pod_ip", "container_ids"}}
    return canonical({"image": item["image"], "details": details})


def canonical(value):
    if isinstance(value, dict):
        return {key: canonical(child) for key, child in value.items()}
    if isinstance(value, list):
        return sorted((canonical(child) for child in value), key=lambda child: json.dumps(child, sort_keys=True))
    return value


def difference(before, after, prefix=""):
    changes = []
    for key in sorted(before.keys() | after.keys()):
        path = f"{prefix}.{key}" if prefix else key
        old, new = before.get(key), after.get(key)
        if isinstance(old, dict) and isinstance(new, dict):
            changes.extend(difference(old, new, path))
        elif old != new:
            changes.append({"field": path, "before": old, "after": new})
    return changes


def record_signal(db, key, kind, title, severity, evidence, now, occurred_at=None):
    """Group new signals by workload and a 30 minute ingestion-time idle window.

    A temporal relationship is evidence for investigation, not proof of an attack.
    Call within the caller's write transaction to avoid duplicate incident creation.
    """
    key = key or "unknown"
    cutoff = (datetime.fromisoformat(now) - timedelta(minutes=30)).isoformat(timespec="seconds")
    incident = db.execute("""SELECT * FROM incidents WHERE container_key=?
        AND status!='resolved' AND last_seen>=? ORDER BY id DESC LIMIT 1""", (key, cutoff)).fetchone()
    if incident:
        ident = incident["id"]
        highest = max((severity, incident["severity"]), key=lambda s: SEVERITY.get(s, 0))
        db.execute("UPDATE incidents SET last_seen=?,severity=? WHERE id=?", (now, highest, ident))
    else:
        workload = db.execute("SELECT name FROM containers WHERE key=?", (key,)).fetchone()
        name = workload["name"] if workload else key
        ident = db.execute("""INSERT INTO incidents(container_key,title,severity,status,first_seen,last_seen)
            VALUES(?,?,?,'open',?,?)""", (key, f"Investigation: {name}", severity, now, now)).lastrowid
    db.execute("""INSERT INTO incident_entries(incident_id,kind,title,severity,evidence,occurred_at,received_at)
        VALUES(?,?,?,?,?,?,?)""", (ident, kind, title, severity, json.dumps(evidence), occurred_at or now, now))
    return ident


SCHEMA = """
CREATE TABLE IF NOT EXISTS configuration_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, container_key TEXT NOT NULL,
    snapshot TEXT NOT NULL, changes TEXT NOT NULL, observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_workload ON configuration_history(container_key,id DESC);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT, container_key TEXT NOT NULL, title TEXT NOT NULL,
    severity TEXT NOT NULL, status TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_workload ON incidents(container_key,last_seen DESC);
CREATE TABLE IF NOT EXISTS incident_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id),
    kind TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT NOT NULL,
    occurred_at TEXT NOT NULL, received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_entries ON incident_entries(incident_id,occurred_at,id);
CREATE TABLE IF NOT EXISTS image_scans (
    image_ref TEXT PRIMARY KEY, result TEXT NOT NULL, scanned_at TEXT NOT NULL
);
"""
