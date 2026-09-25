import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


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

    def upsert_container(self, item):
        now = utcnow()
        with self.connection() as db:
            db.execute("""
                INSERT INTO containers(key,source,name,namespace,image,state,details,restarts,first_seen,last_seen)
                VALUES(:key,:source,:name,:namespace,:image,:state,:details,:restarts,:now,:now)
                ON CONFLICT(key) DO UPDATE SET name=excluded.name, namespace=excluded.namespace,
                image=excluded.image, state=excluded.state, details=excluded.details,
                restarts=excluded.restarts, last_seen=excluded.last_seen
            """, {**item, "details": json.dumps(item.get("details", {})), "now": now})

    def set_state(self, key, state):
        with self.connection() as db:
            db.execute("UPDATE containers SET state=?,last_seen=? WHERE key=?", (state, utcnow(), key))

    def add_event(self, event_key, source, container_key, kind, message, severity="info", occurred_at=None):
        with self.connection() as db:
            result = db.execute("""INSERT OR IGNORE INTO events
                (event_key,source,container_key,kind,message,severity,occurred_at)
                VALUES(?,?,?,?,?,?,?)""", (event_key, source, container_key, kind, message, severity, occurred_at or utcnow()))
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

    def alert(self, fingerprint, source, container_key, rule_id, severity, title, description, recommendation, score=0, repeat=False):
        now = utcnow()
        with self.connection() as db:
            db.execute("""INSERT INTO alerts
                (fingerprint,source,container_key,rule_id,severity,title,description,recommendation,score,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET count=count+?,last_seen=excluded.last_seen,
                severity=excluded.severity,description=excluded.description,score=excluded.score,
                status=CASE WHEN status='resolved' THEN 'open' ELSE status END
            """, (fingerprint, source, container_key, rule_id, severity, title, description,
                  recommendation, score, now, now, int(repeat)))

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
            return self._rows("SELECT * FROM events WHERE container_key=? ORDER BY occurred_at DESC,id DESC LIMIT ?", (key, limit))
        return self._rows("SELECT * FROM events ORDER BY occurred_at DESC,id DESC LIMIT ?", (limit,))

    def summary(self):
        with self.connection() as db:
            containers = db.execute("SELECT COUNT(*) FROM containers WHERE state NOT IN ('exited','deleted','stopped')").fetchone()[0]
            open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            critical = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'").fetchone()[0]
            events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            sources = [dict(r) for r in db.execute("SELECT source,COUNT(*) AS count FROM containers GROUP BY source")]
        return {"containers": containers, "open_alerts": open_alerts, "critical_alerts": critical,
                "events": events, "sources": sources}
