import copy
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest
from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.collectors import kubernetes_item
from sentinel.detect import inspect_configuration
from sentinel.runtime import FalcoEvent, ingest
from sentinel.scanning import ImageScanner, run_trivy, sanitize_report
from sentinel.store import Store

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
CONTAINER_ID = "c" * 64


@pytest.fixture
def item():
    return {"key": f"docker:{CONTAINER_ID}", "source": "docker", "name": "web", "namespace": "",
            "image": "example/web:latest", "state": "running", "restarts": 0,
            "details": {"privileged": False, "root_user": False,
                        "images": [{"name": "web", "reference": "example/web:latest", "digest": DIGEST}]}}


@pytest.fixture
def store(tmp_path, item):
    result = Store(tmp_path / "monitor.db")
    result.upsert_container(item)
    return result


def falco(**changes):
    data = {"rule": "Terminal shell in container", "priority": "Warning", "time": "2026-11-16T12:00:00.123456789Z",
            "output_fields": {"container.id": CONTAINER_ID[:12], "proc.name": "sh", "evt.type": "execve",
                              "proc.cmdline": "sh --password=DO-NOT-STORE"}}
    return FalcoEvent(**{**data, **changes})


def report():
    return {"Results": [{"Target": "libssl", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-TEST", "PkgName": "libssl", "Severity": "HIGH", "InstalledVersion": "1", "FixedVersion": "2"}],
        "Secrets": [{"RuleID": "test-token", "Severity": "CRITICAL", "Title": "Test secret",
                     "Match": "DO-NOT-STORE", "Code": {"Lines": [{"Content": "DO-NOT-STORE"}]}}]}]}


def test_history_diff_restart_noise_and_immutable_digest(store, item):
    assert len(store.configuration_history(item["key"])) == 1
    item["restarts"] = 3
    store.upsert_container(item)
    assert len(store.configuration_history(item["key"])) == 1
    item["details"]["privileged"] = True
    store.upsert_container(item)
    entry = store.configuration_history(item["key"])[0]
    assert entry["changes"] == [{"field": "details.privileged", "before": False, "after": True}]
    item["details"]["images"][0]["digest"] = OTHER_DIGEST
    store.upsert_container(item)
    assert len(store.configuration_history(item["key"])) == 3
    assert store.events(key=item["key"])[0]["kind"] == "configuration_change"
    assert len(store.incidents()) == 1
    assert len(store.configuration_history(item["key"], limit=1, before=entry["id"])) == 1


def test_history_list_order_and_volatile_fields_do_not_create_noise(store, item):
    item["details"]["mounts"] = [{"target": "/a"}, {"target": "/b"}]
    store.upsert_container(item)
    count = len(store.configuration_history(item["key"]))
    item["details"]["mounts"].reverse()
    item["details"]["pod_ip"] = "10.0.0.2"
    item["details"]["container_ids"] = ["new-runtime-id"]
    store.upsert_container(item)
    assert len(store.configuration_history(item["key"])) == count


def test_falco_deduplication_sanitization_and_cross_rule_incident(store, item):
    first = ingest(store, falco())
    assert first["accepted"]
    assert ingest(store, falco())["duplicate"]
    ingest(store, falco(rule="Write below /etc", time="2026-11-16T12:01:00Z"))
    assert len(store.events()) == 2
    assert len(store.alerts()) == 2
    assert len(store.incidents()) == 1
    detail = store.incident(store.incidents()[0]["id"])
    assert len(detail["timeline"]) == 2
    assert "DO-NOT-STORE" not in json.dumps(detail)
    assert "DO-NOT-STORE" not in json.dumps(store.events())
    assert detail["timeline"][0]["evidence"]["fields"]["proc.name"] == "sh"


def test_concurrent_runtime_delivery_is_atomic(store):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: ingest(store, falco()), range(8)))
    assert sum(result["accepted"] for result in results) == 1
    assert store.alerts()[0]["count"] == 1
    assert store.incidents()[0]["signal_count"] == 1


@pytest.mark.parametrize("changes", [
    {"output_fields": {"container.id": "host"}}, {"output_fields": {"container.id": "unknown"}},
    {"time": "not-a-time"}, {"time": "2026-11-16T12:00:00"}, {"priority": "invented"},
])
def test_invalid_falco_creates_no_data(store, changes):
    with pytest.raises(ValueError):
        ingest(store, falco(**changes))
    assert store.events() == []
    assert store.incidents() == []


def test_ambiguous_runtime_identity_rejected(store, item):
    other = copy.deepcopy(item)
    other["key"] = "k8s:pod"
    other["source"] = "kubernetes"
    other["details"]["container_ids"] = [CONTAINER_ID]
    store.upsert_container(other)
    with pytest.raises(ValueError, match="ambiguous"):
        ingest(store, falco())


def test_incident_idle_window_resolution_and_snapshot_evidence(store, item):
    item["details"]["privileged"] = True
    store.upsert_container(item)
    inspect_configuration(store, item)
    first = store.incidents()[0]
    inspect_configuration(store, item)
    assert store.incidents()[0]["signal_count"] == first["signal_count"]
    with store.connection() as db:
        db.execute("UPDATE incidents SET last_seen=?", ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),))
    ingest(store, falco())
    assert len(store.incidents()) == 2
    current = store.incidents()[0]
    store.set_incident_status(current["id"], "resolved")
    ingest(store, falco(time="2026-11-16T12:02:00Z"))
    assert len(store.incidents()) == 3
    history_incident = store.incident(first["id"])
    assert any(entry["evidence"].get("changes") for entry in history_incident["timeline"])
    assert store.incident(first["id"], limit=1)["next_before"] is not None


def test_legacy_database_migration_preserves_data_and_backfills_once(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,event_key TEXT UNIQUE NOT NULL,
            source TEXT NOT NULL,container_key TEXT,kind TEXT NOT NULL,message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',occurred_at TEXT NOT NULL)""")
        db.execute("INSERT INTO events(event_key,source,kind,message,occurred_at) VALUES('legacy','docker','start','old event','2026-01-01')")
    store = Store(path)
    assert store.events()[0]["message"] == "old event"
    assert store.events()[0]["evidence"] == {}
    store.alert("legacy-finding", "docker", "docker:old", "privileged", "critical", "Privileged", "old finding", "remove")
    with store.connection() as db:
        db.execute("DELETE FROM incident_entries")
        db.execute("DELETE FROM incidents")
        db.execute("PRAGMA user_version=0")
    migrated = Store(path)
    assert migrated.incidents()[0]["signal_count"] == 1
    assert migrated.incident(migrated.incidents()[0]["id"])["timeline"][0]["evidence"]["imported"]
    assert Store(path).incidents()[0]["signal_count"] == 1


def test_trivy_sanitization_and_fixed_versions():
    result = sanitize_report(report())
    assert result["counts"]["critical"] == 1
    assert result["counts"]["high"] == 1
    assert result["findings"][0]["fixed_version"] == "2"
    assert "DO-NOT-STORE" not in json.dumps(result)
    assert result["findings"][1]["value"] == "[REDACTED]"


def test_scanner_deduplicates_jobs_caches_and_creates_findings(store, item, monkeypatch):
    started, release = threading.Event(), threading.Event()
    calls = []
    def scan(ref):
        calls.append(ref); started.set()
        assert release.wait(timeout=5)
        return sanitize_report(report())
    monkeypatch.setattr("sentinel.scanning.run_trivy", scan)
    scanner = ImageScanner(store)
    monkeypatch.setattr(scanner, "available", lambda: True)
    try:
        assert scanner.request(item)[0]["status"] == "queued"
        assert started.wait(timeout=5)
        scanner.request(item)
        release.set()
    finally:
        release.set(); scanner.close()
    assert calls == [DIGEST]
    assert scanner.results(item)[0]["status"] == "complete"
    assert store.alerts()[0]["source"] == "trivy"
    assert "DO-NOT-STORE" not in json.dumps(store.image_scan(DIGEST))
    second = ImageScanner(store)
    monkeypatch.setattr(second, "available", lambda: True)
    try:
        assert second.request(item)[0]["status"] == "complete"
        assert calls == [DIGEST]
        assert store.incidents()[0]["signal_count"] == 1
    finally:
        second.close()


def test_scanner_errors_and_stale_results(store, item, monkeypatch):
    scanner = ImageScanner(store)
    monkeypatch.setattr(scanner, "available", lambda: True)
    monkeypatch.setattr("sentinel.scanning.run_trivy", lambda _: (_ for _ in ()).throw(RuntimeError("Registry unavailable")))
    scanner.request(item)
    scanner.close()
    assert scanner.results(item)[0]["status"] == "error"
    assert store.image_scan(DIGEST) is None
    scanner._apply(item, DIGEST, sanitize_report(report()))
    item["details"]["images"][0]["digest"] = OTHER_DIGEST
    store.upsert_container(item)
    assert store.alerts()[0]["status"] == "resolved"


def test_trivy_cli_uses_immutable_ref_no_shell_and_removes_raw_output(monkeypatch):
    captured = {}
    monkeypatch.setattr("sentinel.scanning.shutil.which", lambda _: "trivy.exe")
    def run(args, **kwargs):
        captured.update(args=args, kwargs=kwargs)
        from pathlib import Path
        output = Path(args[args.index("--output") + 1])
        captured["output"] = output
        output.write_text(json.dumps(report()), encoding="utf-8")
        return NS(returncode=0)
    monkeypatch.setattr("sentinel.scanning.subprocess.run", run)
    assert run_trivy(DIGEST)["total"] == 2
    assert captured["args"][-2:] == ["--", DIGEST]
    assert not captured["kwargs"].get("shell")
    assert not captured["output"].exists()
    with pytest.raises(ValueError):
        run_trivy("alpine:latest")


def test_security_api_authorization_size_limits_and_validation(store, item, monkeypatch):
    monkeypatch.delenv("SENTINEL_FALCO_TOKEN", raising=False)
    with TestClient(create_app(store, start_collectors=False)) as client:
        payload = falco().model_dump()
        assert client.post("/api/runtime/falco", json=payload).status_code == 503
        monkeypatch.setenv("SENTINEL_FALCO_TOKEN", "unit-test-token")
        assert client.post("/api/runtime/falco", json=payload).status_code == 401
        headers = {"Authorization": "Bearer unit-test-token"}
        assert client.post("/api/runtime/falco", json=payload, headers=headers).status_code == 200
        invalid = client.post("/api/runtime/falco", json={"rule": {"secret": "DO-NOT-STORE"}}, headers=headers)
        assert invalid.status_code == 422 and "DO-NOT-STORE" not in invalid.text
        assert client.post("/api/runtime/falco", content="x" * (256 * 1024 + 1), headers=headers).status_code == 413
        incident = client.get("/api/incidents").json()[0]
        assert client.get(f"/api/incidents/{incident['id']}").json()["timeline"]
        assert client.post(f"/api/incidents/{incident['id']}/status?status=resolved").status_code == 200
        assert client.get("/api/incidents/99999").status_code == 404
        assert client.get(f"/api/history/{item['key']}").json()[0]["snapshot"]
        assert client.get("/api/history/missing").status_code == 404
        assert client.get(f"/api/history/{item['key']}?limit=0").status_code == 422
        assert client.post("/api/scans/missing").status_code == 404
        assert client.get(f"/api/containers/{item['key']}").json()["image_scans"]


def test_kubernetes_sidecars_init_containers_and_runtime_identity():
    from kubernetes.client import V1Container, V1ContainerStatus, V1ObjectMeta, V1Pod, V1PodSpec, V1PodStatus, V1SecurityContext
    pod = V1Pod(metadata=V1ObjectMeta(uid="uid", name="web", namespace="default"),
                spec=V1PodSpec(containers=[V1Container(name="web", image="example/web:1")],
                               init_containers=[V1Container(name="setup", image="alpine:3", security_context=V1SecurityContext(privileged=True))]),
                status=V1PodStatus(phase="Running", container_statuses=[V1ContainerStatus(
                    name="web", image="example/web:1", image_id=f"docker-pullable://example/web@{DIGEST}",
                    container_id=f"containerd://{CONTAINER_ID}", ready=True, restart_count=0)]))
    normalized = kubernetes_item(pod)
    assert normalized["details"]["privileged"]
    assert normalized["details"]["container_ids"] == [CONTAINER_ID]
    assert normalized["details"]["images"][0]["digest"] == f"example/web@{DIGEST}"
    assert len(normalized["details"]["images"]) == 2


def test_shared_digest_scan_attaches_to_all_subscribers_and_skips_replaced_image(store, item, monkeypatch):
    started, release = threading.Event(), threading.Event()
    def run(_):
        started.set()
        assert release.wait(timeout=5)
        return sanitize_report(report())
    monkeypatch.setattr("sentinel.scanning.run_trivy", run)
    scanner = ImageScanner(store)
    monkeypatch.setattr(scanner, "available", lambda: True)
    other = copy.deepcopy(item)
    other["key"] = "docker:" + "d" * 64
    other["name"] = "worker"
    store.upsert_container(other)
    try:
        scanner.request(item)
        assert started.wait(timeout=5)
        scanner.request(other)
        item["details"]["images"][0]["digest"] = OTHER_DIGEST
        store.upsert_container(item)
    finally:
        release.set(); scanner.close()
    assert {alert["container_key"] for alert in store.alerts()} == {other["key"]}


def test_clean_rescan_resolves_previous_findings_and_changed_report_adds_evidence(store, item, monkeypatch):
    results = [sanitize_report(report()), sanitize_report(report()), {"findings": [], "total": 0, "counts": {}}]
    results[1]["findings"][0]["id"] = "CVE-CHANGED-SAME-COUNT"
    monkeypatch.setattr("sentinel.scanning.run_trivy", lambda _: results.pop(0))
    for expected_count in (1, 2, 2):
        scanner = ImageScanner(store)
        monkeypatch.setattr(scanner, "available", lambda: True)
        scanner.request(item, force=True)
        scanner.executor.shutdown(wait=True)
        scanner.close()
        assert store.incidents()[0]["signal_count"] == expected_count
    assert store.alerts()[0]["status"] == "resolved"


def test_auto_scan_error_backoff_and_manual_retry(store, item, monkeypatch):
    calls = []
    def failing(ref):
        calls.append(ref)
        raise RuntimeError("Registry unavailable")
    monkeypatch.setattr("sentinel.scanning.run_trivy", failing)
    scanner = ImageScanner(store)
    monkeypatch.setattr(scanner, "available", lambda: True)
    scanner.request(item)
    # Wait for the real worker without relying on a timing-dependent sleep.
    scanner.executor.submit(lambda: None).result(timeout=5)
    scanner.request(item)
    assert len(calls) == 1
    scanner.request(item, force=True)
    scanner.executor.submit(lambda: None).result(timeout=5)
    scanner.close()
    assert len(calls) == 2


def test_scan_queue_is_bounded(store, item, monkeypatch):
    release = threading.Event()
    def run(_):
        assert release.wait(timeout=5)
        return {"findings": [], "counts": {}, "total": 0}
    monkeypatch.setattr("sentinel.scanning.run_trivy", run)
    scanner = ImageScanner(store)
    monkeypatch.setattr(scanner, "available", lambda: True)
    try:
        for number in range(8):
            item["details"]["images"][0]["digest"] = "sha256:" + f"{number:064x}"
            scanner.request(item)
        item["details"]["images"][0]["digest"] = "sha256:" + "f" * 64
        with pytest.raises(RuntimeError, match="queue is full"):
            scanner.request(item)
    finally:
        release.set(); scanner.close()
