import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .investigations import SCHEMA, configuration, difference, record_signal


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def init(self):
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS containers (
                    key TEXT PRIMARY KEY, source TEXT NOT NULL, name TEXT NOT NULL,
                    namespace TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'unknown', details TEXT NOT NULL DEFAULT '{}',
                    cpu_percent REAL, memory_bytes INTEGER, restarts INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE NOT NULL,
                    source TEXT NOT NULL, container_key TEXT, kind TEXT NOT NULL,
                    message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
                    occurred_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, container_key TEXT NOT NULL,
                    cpu_percent REAL, memory_bytes INTEGER, sampled_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_samples_container ON samples(container_key, id DESC);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT UNIQUE NOT NULL,
                    source TEXT NOT NULL, container_key TEXT, rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
                    recommendation TEXT NOT NULL, score REAL NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'open', count INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_last ON alerts(last_seen DESC);
            """)
            db.executescript(SCHEMA)
            columns = {row[1] for row in db.execute("PRAGMA table_info(events)")}
            if "evidence" not in columns:
                db.execute("ALTER TABLE events ADD COLUMN evidence TEXT NOT NULL DEFAULT '{}'")
            if db.execute("PRAGMA user_version").fetchone()[0] < 1:
                if not db.in_transaction:
                    db.execute("BEGIN IMMEDIATE")
                for alert in db.execute("SELECT * FROM alerts WHERE status!='resolved'").fetchall():
                    record_signal(db, alert["container_key"], "alert", alert["title"], alert["severity"],
                                  {"alert_id": alert["id"], "rule_id": alert["rule_id"],
                                   "description": alert["description"], "recommendation": alert["recommendation"],
                                   "imported": True}, utcnow(), alert["first_seen"])
                db.execute("PRAGMA user_version=1")

    def upsert_container(self, item):
        now = utcnow()
        with self.connection() as db:
            # Acquire the writer before reading the previous snapshot.
            db.execute("BEGIN IMMEDIATE")
            snapshot = configuration(item)
            previous = db.execute("SELECT snapshot FROM configuration_history WHERE container_key=? ORDER BY id DESC LIMIT 1",
                                  (item["key"],)).fetchone()
            changes = difference(json.loads(previous["snapshot"]), snapshot) if previous else []
            db.execute("""
                INSERT INTO containers(key,source,name,namespace,image,state,details,restarts,first_seen,last_seen)
                VALUES(:key,:source,:name,:namespace,:image,:state,:details,:restarts,:now,:now)
                ON CONFLICT(key) DO UPDATE SET name=excluded.name, namespace=excluded.namespace,
                image=excluded.image, state=excluded.state, details=excluded.details,
                restarts=excluded.restarts, last_seen=excluded.last_seen
            """, {**item, "details": json.dumps(item.get("details", {})), "now": now})
            refs = {image.get("digest", "") for image in item.get("details", {}).get("images", [])}
            for alert in db.execute("SELECT id,fingerprint FROM alerts WHERE container_key=? AND rule_id='image_scan'", (item["key"],)).fetchall():
                if not any(alert["fingerprint"] == f"{item['key']}:image_scan:{ref}" for ref in refs):
                    db.execute("UPDATE alerts SET status='resolved' WHERE id=?", (alert["id"],))
            if not previous or changes:
                ident = db.execute("""INSERT INTO configuration_history(container_key,snapshot,changes,observed_at)
                    VALUES(?,?,?,?)""", (item["key"], json.dumps(snapshot), json.dumps(changes), now)).lastrowid
                if changes:
                    title = "Configuration changed: " + ", ".join(c["field"] for c in changes)
                    evidence = {"history_id": ident, "changes": changes}
                    db.execute("""INSERT INTO events(event_key,source,container_key,kind,message,severity,occurred_at,evidence)
                        VALUES(?,?,?,'configuration_change',?,'info',?,?)""",
                               (f"configuration:{ident}", item["source"], item["key"], title, now, json.dumps(evidence)))
                    record_signal(db, item["key"], "configuration", title, "info", evidence, now)

    def set_state(self, key, state):
        with self.connection() as db:
            db.execute("UPDATE containers SET state=?,last_seen=? WHERE key=?", (state, utcnow(), key))

    def add_event(self, event_key, source, container_key, kind, message, severity="info", occurred_at=None, evidence=None):
        with self.connection() as db:
            result = db.execute("""INSERT OR IGNORE INTO events
                (event_key,source,container_key,kind,message,severity,occurred_at,evidence)
                VALUES(?,?,?,?,?,?,?,?)""", (event_key, source, container_key, kind, message, severity, occurred_at or utcnow(), json.dumps(evidence or {})))
            return result.rowcount > 0

    def add_sample(self, key, cpu_percent=None, memory_bytes=None):
        now = utcnow()
        with self.connection() as db:
            db.execute("INSERT INTO samples(container_key,cpu_percent,memory_bytes,sampled_at) VALUES(?,?,?,?)",
                       (key, cpu_percent, memory_bytes, now))
            db.execute("UPDATE containers SET cpu_percent=?,memory_bytes=?,last_seen=? WHERE key=?",
                       (cpu_percent, memory_bytes, now, key))
            db.execute("""DELETE FROM samples WHERE id IN (
                SELECT id FROM samples WHERE container_key=? ORDER BY id DESC LIMIT -1 OFFSET 120
            )""", (key,))

    def recent_samples(self, key, limit=30):
        with self.connection() as db:
            rows = db.execute("SELECT * FROM samples WHERE container_key=? ORDER BY id DESC LIMIT ?", (key, limit)).fetchall()
            return [dict(r) for r in reversed(rows)]

    def alert(self, fingerprint, source, container_key, rule_id, severity, title, description, recommendation, score=0, repeat=False, evidence=None, occurred_at=None):
        now = utcnow()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
            db.execute("""INSERT INTO alerts
                (fingerprint,source,container_key,rule_id,severity,title,description,recommendation,score,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET count=count+?,last_seen=excluded.last_seen,
                severity=excluded.severity,description=excluded.description,score=excluded.score,
                status=CASE WHEN status='resolved' THEN 'open' ELSE status END
            """, (fingerprint, source, container_key, rule_id, severity, title, description,
                  recommendation, score, now, now, int(repeat)))
            if not previous or repeat or previous["status"] == "resolved" or previous["description"] != description or previous["severity"] != severity:
                alert_id = db.execute("SELECT id FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()["id"]
                record_signal(db, container_key, "alert", title, severity,
                              {"alert_id": alert_id, "rule_id": rule_id, "description": description,
                               "recommendation": recommendation, **(evidence or {})}, now, occurred_at)

    def set_alert_status(self, alert_id, status):
        with self.connection() as db:
            result = db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
            return result.rowcount > 0

    def resolve_configuration(self, key, active_rules):
        rules = ("privileged", "docker_socket", "host_pid", "host_network", "host_path",
                 "root_user", "privilege_escalation", "capabilities")
        with self.connection() as db:
            for rule in rules:
                if rule not in active_rules:
                    db.execute("UPDATE alerts SET status='resolved' WHERE container_key=? AND rule_id=? AND status!='resolved'",
                               (key, rule))

    def alert_by_id(self, alert_id):
        rows = self._rows("SELECT * FROM alerts WHERE id=?", (alert_id,))
        return rows[0] if rows else None

    def _rows(self, query, params=()):
        with self.connection() as db:
            return [dict(r) for r in db.execute(query, params).fetchall()]

    def containers(self, limit=200):
        rows = self._rows("""SELECT c.*,COALESCE((SELECT MAX(CASE a.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END)
            FROM alerts a WHERE a.container_key=c.key AND a.status='open'),0) AS risk
            FROM containers c ORDER BY risk DESC,c.last_seen DESC LIMIT ?""", (limit,))
        for row in rows:
            row["details"] = json.loads(row["details"])
        return rows

    def container(self, key):
        rows = self._rows("SELECT * FROM containers WHERE key=?", (key,))
        if not rows:
            return None
        rows[0]["details"] = json.loads(rows[0]["details"])
        return rows[0]

    def alerts(self, limit=200, status=None, key=None):
        where, params = [], []
        if status:
            where.append("status=?")
            params.append(status)
        if key:
            where.append("container_key=?")
            params.append(key)
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,last_seen DESC LIMIT ?"
        return self._rows(sql, (*params, limit))

    def events(self, limit=200, key=None):
        if key:
            rows = self._rows("SELECT * FROM events WHERE container_key=? ORDER BY occurred_at DESC,id DESC LIMIT ?", (key, limit))
        else:
            rows = self._rows("SELECT * FROM events ORDER BY occurred_at DESC,id DESC LIMIT ?", (limit,))
        for row in rows:
            row["evidence"] = json.loads(row["evidence"])
        return rows

    def configuration_history(self, key, limit=50, before=None):
        rows = self._rows("""SELECT * FROM configuration_history WHERE container_key=?
            AND (? IS NULL OR id<?) ORDER BY id DESC LIMIT ?""", (key, before, before, limit))
        for row in rows:
            row["snapshot"] = json.loads(row["snapshot"])
            row["changes"] = json.loads(row["changes"])
        return rows

    def incidents(self, status=None, key=None, limit=100):
        return self._rows("""SELECT i.*, (SELECT COUNT(*) FROM incident_entries e WHERE e.incident_id=i.id) AS signal_count
            FROM incidents i WHERE (? IS NULL OR status=?) AND (? IS NULL OR container_key=?)
            ORDER BY last_seen DESC,id DESC LIMIT ?""", (status, status, key, key, limit))

    def incident(self, ident, limit=200, before=None):
        rows = self._rows("SELECT * FROM incidents WHERE id=?", (ident,))
        if not rows:
            return None
        item = rows[0]
        item["timeline"] = self._rows("""SELECT * FROM incident_entries WHERE incident_id=?
            AND (? IS NULL OR id<?) ORDER BY id DESC LIMIT ?""", (ident, before, before, limit))
        for entry in item["timeline"]:
            entry["evidence"] = json.loads(entry["evidence"])
        item["next_before"] = min((entry["id"] for entry in item["timeline"]), default=None) if len(item["timeline"]) == limit else None
        item["timeline"].sort(key=lambda entry: (entry["occurred_at"], entry["id"]))
        return item

    def set_incident_status(self, ident, status):
        with self.connection() as db:
            return db.execute("UPDATE incidents SET status=? WHERE id=?", (status, ident)).rowcount > 0

    def image_scan(self, image_ref):
        rows = self._rows("SELECT * FROM image_scans WHERE image_ref=?", (image_ref,))
        if rows:
            return {**rows[0], "result": json.loads(rows[0]["result"])}
        return None

    def save_image_scan(self, image_ref, result):
        with self.connection() as db:
            db.execute("""INSERT INTO image_scans(image_ref,result,scanned_at) VALUES(?,?,?)
                ON CONFLICT(image_ref) DO UPDATE SET result=excluded.result,scanned_at=excluded.scanned_at""",
                       (image_ref, json.dumps(result), utcnow()))

    def runtime_workload(self, container_id):
        # Falco normally emits a 12-character ID; reject ambiguous prefixes.
        matches = []
        for item in self._rows("SELECT key,details FROM containers WHERE state NOT IN ('deleted','exited','stopped')"):
            identities = json.loads(item["details"]).get("container_ids", [])
            if item["key"].startswith("docker:"):
                identities.append(item["key"].split(":", 1)[1])
            if any(ident == container_id or (len(container_id) >= 12 and ident.startswith(container_id)) for ident in identities):
                matches.append(item["key"])
        return self.container(matches[0]) if len(matches) == 1 else None

    def add_runtime_event(self, event_key, workload, rule, title, message, severity, occurred_at, evidence):
        now = utcnow()
        key = workload["key"]
        rule_id = "falco:" + rule
        advice = "Inspect the process and file evidence, confirm whether this activity is expected, and contain the workload if necessary."
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            inserted = db.execute("""INSERT OR IGNORE INTO events
                (event_key,source,container_key,kind,message,severity,occurred_at,evidence)
                VALUES(?,'falco',?,'runtime',?,?,?,?)""",
                                  (event_key, key, message, severity, occurred_at, json.dumps(evidence)))
            if not inserted.rowcount:
                return False
            fingerprint = f"{key}:{rule_id}"
            db.execute("""INSERT INTO alerts(fingerprint,source,container_key,rule_id,severity,title,
                description,recommendation,score,first_seen,last_seen)
                VALUES(?,'falco',?,?,?,?,?,?,85,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                count=count+1,last_seen=excluded.last_seen,severity=excluded.severity,
                description=excluded.description,status=CASE WHEN status='resolved' THEN 'open' ELSE status END""",
                       (fingerprint, key, rule_id, severity, title, message, advice, now, now))
            alert_id = db.execute("SELECT id FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()["id"]
            record_signal(db, key, "runtime", title, severity,
                          {**evidence, "alert_id": alert_id, "rule_id": rule_id, "recommendation": advice}, now, occurred_at)
        return True

    def summary(self):
        with self.connection() as db:
            containers = db.execute("SELECT COUNT(*) FROM containers WHERE state NOT IN ('exited','deleted','stopped')").fetchone()[0]
            open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            critical = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'").fetchone()[0]
            events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            sources = [dict(r) for r in db.execute("SELECT source,COUNT(*) AS count FROM containers GROUP BY source")]
        return {"containers": containers, "open_alerts": open_alerts, "critical_alerts": critical,
                "events": events, "sources": sources}
