from types import SimpleNamespace as NS

from fastapi.testclient import TestClient

from sentinel.api import create_app
from sentinel.collectors import docker_cpu, docker_item, kubernetes_item, quantity
from sentinel.demo import seed
from sentinel.detect import inspect_configuration, inspect_event, inspect_sample
from sentinel.explain import explain
from sentinel.store import Store


def test_demo_data_and_api(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    store = Store(tmp_path / "test.db")
    seed(store)
    app = create_app(store, start_collectors=False)
    with TestClient(app) as client:
        assert client.get("/api/health").json()["status"] == "ok"
        summary = client.get("/api/summary").json()
        assert summary["containers"] == 3
        assert summary["critical_alerts"] >= 1
        containers = client.get("/api/containers").json()
        assert len(containers) == 3
        key = containers[0]["key"]
        detail = client.get(f"/api/containers/{key}").json()
        assert detail["samples"]
        alerts = client.get("/api/alerts?status=open").json()
        assert any(a["rule_id"] == "cpu_percent_anomaly" for a in alerts)
        assert any(a["rule_id"] == "oom" for a in alerts)
        first = alerts[0]
        assert client.post(f"/api/alerts/{first['id']}/status?status=acknowledged").status_code == 200
        assert client.post(f"/api/alerts/{first['id']}/explain").status_code == 503
        assert client.get("/api/reports/incident").status_code == 200
        assert "Container security incident report" in client.get("/api/reports/incident").text
        assert client.get("/api/containers/missing").status_code == 404


def test_configuration_deduplicates_and_event_correlates(tmp_path):
    store = Store(tmp_path / "test.db")
    item = {"key": "docker:abc", "source": "docker", "name": "unsafe", "namespace": "",
            "image": "alpine", "state": "running", "restarts": 0,
            "details": {"privileged": True, "root_user": True, "dangerous_capabilities": []}}
    store.upsert_container(item)
    inspect_configuration(store, item)
    inspect_configuration(store, item)
    findings = store.alerts()
    assert {a["rule_id"] for a in findings} == {"privileged", "root_user"}
    assert all(a["count"] == 1 for a in findings)
    for number in (1, 2):
        event_key = f"test:{number}"
        if store.add_event(event_key, "docker", item["key"], "oom", "Out of memory", "warning"):
            inspect_event(store, item, "oom", "Out of memory", event_key)
    oom = next(a for a in store.alerts() if a["rule_id"] == "oom")
    assert oom["count"] == 2
    item["details"]["privileged"] = False
    inspect_configuration(store, item)
    assert next(a for a in store.alerts() if a["rule_id"] == "privileged")["status"] == "resolved"


def test_normalization_and_quantities():
    container = NS(id="abc", name="unsafe", attrs={
        "Config": {"Image": "alpine", "User": "0"},
        "HostConfig": {"Privileged": True, "PidMode": "host", "NetworkMode": "bridge", "CapAdd": ["NET_ADMIN"]},
        "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
        "State": {"Status": "running"}, "RestartCount": 2,
    })
    item = docker_item(container)
    assert item["details"]["docker_socket"]
    assert item["details"]["dangerous_capabilities"] == ["NET_ADMIN"]
    assert docker_cpu({"cpu_stats": {"cpu_usage": {"total_usage": 200}, "system_cpu_usage": 1000, "online_cpus": 2},
                       "precpu_stats": {"cpu_usage": {"total_usage": 100}, "system_cpu_usage": 500}}) == 40
    assert quantity("250m") == 0.25
    assert quantity("64Mi") == 64 * 1024 * 1024

    context = NS(privileged=True, run_as_user=0, allow_privilege_escalation=True,
                 capabilities=NS(add=["SYS_ADMIN"]))
    pod = NS(metadata=NS(uid="uid", name="unsafe", namespace="lab"),
             spec=NS(containers=[NS(image="alpine", security_context=context)],
                     security_context=None, volumes=[], host_pid=False, host_network=False,
                     node_name="node1", service_account_name="default"),
             status=NS(phase="Running", container_statuses=[NS(restart_count=1)], pod_ip="10.0.0.1"))
    normalized = kubernetes_item(pod)
    assert normalized["key"] == "k8s:uid"
    assert normalized["details"]["privileged"]
    assert normalized["details"]["root_user"]
    assert normalized["restarts"] == 1


def test_ai_explanation_uses_selected_evidence(monkeypatch):
    captured = {}
    class Response:
        def raise_for_status(self):
            pass
        def json(self):
            return {"output": [{"content": [{"type": "output_text", "text": "Inspect this workload."}]}]}
    def fake_post(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return Response()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("sentinel.explain.requests.post", fake_post)
    result = explain({"title": "Privileged", "severity": "critical", "description": "root access",
                      "recommendation": "drop privilege", "container_key": "docker:abc"},
                     {"name": "workload"}, [{"occurred_at": "now", "message": "started"}])
    assert result == "Inspect this workload."
    assert captured["url"] == "https://api.openai.com/v1/responses"
    assert captured["json"]["store"] is False
    assert "started" in captured["json"]["input"]
