"""Seed a local database so the GUI can be explored without Docker or Kubernetes."""
import argparse
from copy import deepcopy

from .config import DB_PATH
from .detect import inspect_configuration, inspect_event, inspect_sample
from .store import Store
from .runtime import FalcoEvent, ingest


def seed(store):
    workloads = [
        {"key": "docker:demo-unsafe", "source": "docker", "name": "demo-unsafe-web", "namespace": "",
         "image": "alpine:3.20", "state": "running", "restarts": 2,
         "details": {"privileged": True, "root_user": True, "host_pid": False, "host_network": False,
                     "host_path": False, "docker_socket": False, "dangerous_capabilities": ["NET_ADMIN"]}},
        {"key": "k8s:demo-pod", "source": "kubernetes", "name": "demo-risky-pod", "namespace": "sentinel-lab",
         "image": "alpine:3.20", "state": "running", "restarts": 1,
         "details": {"privileged": False, "root_user": True, "host_pid": False, "host_network": False,
                     "host_path": False, "docker_socket": False, "allow_privilege_escalation": True,
                     "dangerous_capabilities": []}},
        {"key": "docker:demo-normal", "source": "docker", "name": "demo-normal-worker", "namespace": "",
         "image": "alpine:3.20", "state": "running", "restarts": 0,
         "details": {"privileged": False, "root_user": False, "host_pid": False, "host_network": False,
                     "host_path": False, "docker_socket": False, "dangerous_capabilities": []}},
    ]
    for item in workloads:
        if item == workloads[0] and not store.container(item["key"]):
            baseline = deepcopy(item)
            baseline["details"]["privileged"] = False
            store.upsert_container(baseline)
        store.upsert_container(item)
        inspect_configuration(store, item)
        for i in range(10):
            inspect_sample(store, item, 4 + i % 3, 32 * 1024 * 1024 + i * 1024 * 1024)
    inspect_sample(store, workloads[0], 85, 180 * 1024 * 1024)
    ingest(store, FalcoEvent(rule="Demo: unexpected shell in container", priority="Warning",
                            time=store.container(workloads[0]["key"])["first_seen"], output_fields={"container.id": "demo-unsafe",
                                                                      "proc.name": "sh", "evt.type": "execve"}))
    event_key = "demo:oom:1"
    if store.add_event(event_key, "docker", workloads[0]["key"], "oom", "demo-unsafe-web: out of memory", "warning"):
        inspect_event(store, workloads[0], "oom", "demo-unsafe-web: out of memory", event_key)
    event_key = "demo:warning:1"
    if store.add_event(event_key, "kubernetes", workloads[1]["key"], "BackOff", "demo-risky-pod: Back-off restarting failed container", "warning"):
        inspect_event(store, workloads[1], "BackOff", "demo-risky-pod: Back-off restarting failed container", event_key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(DB_PATH))
    args = parser.parse_args()
    seed(Store(args.db))
    print(f"Demo data written to {args.db}")
