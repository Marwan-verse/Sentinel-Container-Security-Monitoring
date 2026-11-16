import logging
import os
import threading
import time
from datetime import datetime, timezone

from .detect import inspect_configuration, inspect_event, inspect_sample

log = logging.getLogger(__name__)
SENSITIVE_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_MODULE"}


def docker_item(container):
    attrs = container.attrs
    config = attrs.get("Config") or {}
    host = attrs.get("HostConfig") or {}
    mounts = attrs.get("Mounts") or []
    caps = host.get("CapAdd") or []
    user = str(config.get("User") or "").split(":")[0]
    return {
        "key": f"docker:{container.id}", "source": "docker",
        "name": container.name, "namespace": "", "image": config.get("Image") or "",
        "state": (attrs.get("State") or {}).get("Status") or "unknown", "restarts": attrs.get("RestartCount") or 0,
        "details": {
            "container_ids": [container.id],
            "images": [{"name": container.name, "reference": config.get("Image") or "",
                        "digest": attrs.get("Image") or ""}],
            "privileged": bool(host.get("Privileged")), "host_pid": host.get("PidMode") == "host",
            "host_network": host.get("NetworkMode") == "host",
            "host_path": any(m.get("Type") == "bind" for m in mounts),
            "docker_socket": any("docker.sock" in str(m.get("Source", "")) or "docker.sock" in str(m.get("Destination", "")) for m in mounts),
            "root_user": user in ("", "0", "root"),
            "user": config.get("User") or "",
            "read_only_root_filesystem": bool(host.get("ReadonlyRootfs")),
            "capabilities": sorted(caps), "capabilities_drop": sorted(host.get("CapDrop") or []),
            "security_options": sorted(host.get("SecurityOpt") or []),
            "dangerous_capabilities": sorted(SENSITIVE_CAPS.intersection(caps)),
            "ports": host.get("PortBindings") or {}, "mounts": [{"source": m.get("Source"), "target": m.get("Destination"), "type": m.get("Type"), "read_only": m.get("RW") is False} for m in mounts],
        },
    }


def docker_cpu(stats):
    cpu = stats.get("cpu_stats") or {}
    before = stats.get("precpu_stats") or {}
    used = (cpu.get("cpu_usage") or {}).get("total_usage", 0) - (before.get("cpu_usage") or {}).get("total_usage", 0)
    system = cpu.get("system_cpu_usage", 0) - before.get("system_cpu_usage", 0)
    cores = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    return round(100 * used * cores / system, 2) if used > 0 and system > 0 else 0.0


def docker_memory(stats):
    memory = stats.get("memory_stats") or {}
    return max(0, int(memory.get("usage", 0) - (memory.get("stats") or {}).get("inactive_file", 0)))


def quantity(value):
    """Convert a Kubernetes resource quantity to base units (cores or bytes)."""
    if not value:
        return 0.0
    value = str(value)
    suffixes = {"n": 1e-9, "u": 1e-6, "m": 1e-3, "Ki": 1024, "Mi": 1024**2,
                "Gi": 1024**3, "Ti": 1024**4, "K": 1000, "M": 1000**2, "G": 1000**3}
    for suffix in sorted(suffixes, key=len, reverse=True):
        if value.endswith(suffix):
            return float(value[:-len(suffix)]) * suffixes[suffix]
    return float(value)


def kubernetes_item(pod):
    spec, meta, status = pod.spec, pod.metadata, pod.status
    containers = (spec.containers or []) + (getattr(spec, "init_containers", None) or []) + (getattr(spec, "ephemeral_containers", None) or [])
    statuses = (status.container_statuses or []) + (getattr(status, "init_container_statuses", None) or []) + (getattr(status, "ephemeral_container_statuses", None) or [])
    statuses_by_name = {s.name: s for s in statuses if getattr(s, "name", None)}
    images = []
    for c in containers:
        container_status = statuses_by_name.get(getattr(c, "name", ""))
        image_id = getattr(container_status, "image_id", None) or ""
        image_id = image_id.split("://", 1)[-1]
        images.append({"name": getattr(c, "name", "container"), "reference": c.image,
                       "digest": image_id or (c.image if "@sha256:" in c.image else "")})
    contexts = [c.security_context for c in containers]
    pod_context = spec.security_context
    user_ids = [getattr(c, "run_as_user", None) for c in contexts]
    if pod_context and pod_context.run_as_user is not None:
        user_ids.append(pod_context.run_as_user)
    caps = set()
    for context in contexts:
        if context and context.capabilities and context.capabilities.add:
            caps.update(context.capabilities.add)
    return {
        "key": f"k8s:{meta.uid}", "source": "kubernetes", "name": meta.name,
        "namespace": meta.namespace or "default",
        "image": ", ".join(c.image for c in containers),
        "state": (status.phase or "unknown").lower(),
        "restarts": sum(s.restart_count or 0 for s in (status.container_statuses or [])),
        "details": {
            "container_ids": [s.container_id.split("://", 1)[-1] for s in statuses if getattr(s, "container_id", None)],
            "images": images,
            "pod_security_context": pod_context.to_dict() if pod_context and hasattr(pod_context, "to_dict") else {},
            "host_mounts": [{"name": v.name, "path": v.host_path.path, "type": v.host_path.type}
                            for v in (spec.volumes or []) if v.host_path],
            "container_configuration": [{"name": getattr(c, "name", "container"), "image": c.image,
                                         "security_context": c.security_context.to_dict() if c.security_context and hasattr(c.security_context, "to_dict") else {},
                                         "mounts": [m.to_dict() for m in (getattr(c, "volume_mounts", None) or [])]}
                                        for c in containers],
            "privileged": any(bool(c and c.privileged) for c in contexts),
            "host_pid": bool(spec.host_pid), "host_network": bool(spec.host_network),
            "host_path": any(bool(v.host_path) for v in (spec.volumes or [])),
            "docker_socket": any(v.host_path and "docker.sock" in v.host_path.path for v in (spec.volumes or [])),
            "root_user": 0 in user_ids,
            "allow_privilege_escalation": any(bool(c and c.allow_privilege_escalation) for c in contexts),
            "dangerous_capabilities": sorted(SENSITIVE_CAPS.intersection(caps)),
            "node": spec.node_name, "pod_ip": status.pod_ip,
            "service_account": spec.service_account_name,
        },
    }


class CollectorManager:
    def __init__(self, store, mode="auto", poll_seconds=10, scanner=None):
        self.store = store
        self.mode = mode
        self.poll_seconds = poll_seconds
        self.stop = threading.Event()
        self.health = {"docker": "disabled", "kubernetes": "disabled"}
        self.threads = []
        self.scanner = scanner

    def _scan_images(self, item):
        if self.scanner and os.getenv("SENTINEL_SCAN_IMAGES", "false").lower() == "true":
            try:
                self.scanner.request(item)
            except RuntimeError as exc:
                log.debug("Image scan not queued: %s", exc)

    def start(self):
        if self.mode in ("auto", "docker", "all"):
            self._thread(self._docker_poll, "docker-poll")
            self._thread(self._docker_events, "docker-events")
        if self.mode in ("auto", "kubernetes", "all"):
            self._thread(self._kubernetes_poll, "kubernetes-poll")

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def _thread(self, target, name):
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _docker_client(self):
        import docker
        client = docker.from_env(timeout=8)
        client.ping()
        return client

    def _docker_poll(self):
        while not self.stop.is_set():
            try:
                client = self._docker_client()
                self.health["docker"] = "connected"
                for container in client.containers.list(all=True):
                    if self.stop.is_set():
                        break
                    try:
                        item = docker_item(container)
                        previous = self.store.container(item["key"])
                        self.store.upsert_container(item)
                        inspect_configuration(self.store, item)
                        self._scan_images(item)
                        if previous and item["restarts"] > previous["restarts"]:
                            difference = item["restarts"] - previous["restarts"]
                            self.store.alert(f"{item['key']}:restarts", "docker", item["key"], "restarts", "high",
                                             "Container restarted", f"{item['name']} restarted {difference} time(s).",
                                             "Inspect exit codes, logs, and resource limits.", 70, repeat=True)
                        if item["state"] == "running":
                            stats = container.stats(stream=False)
                            inspect_sample(self.store, item, docker_cpu(stats), docker_memory(stats))
                    except Exception:
                        log.exception("Could not inspect Docker container %s", container.id)
                client.close()
            except Exception as exc:
                self.health["docker"] = f"unavailable: {str(exc)[:100]}"
                log.debug("Docker unavailable: %s", exc)
            self.stop.wait(self.poll_seconds)

    def _docker_events(self):
        while not self.stop.is_set():
            client = None
            try:
                client = self._docker_client()
                since = int(time.time())
                for event in client.events(decode=True, filters={"type": "container"}, since=since):
                    if self.stop.is_set():
                        break
                    ident = event.get("id") or (event.get("Actor") or {}).get("ID")
                    if not ident:
                        continue
                    key = f"docker:{ident}"
                    action = event.get("Action") or event.get("status") or "unknown"
                    attrs = (event.get("Actor") or {}).get("Attributes") or {}
                    name = attrs.get("name") or ident[:12]
                    event_key = f"docker:{event.get('timeNano') or event.get('time')}:{ident}:{action}"
                    item = self.store.container(key)
                    if not item:
                        try:
                            item = docker_item(client.containers.get(ident))
                            self.store.upsert_container(item)
                            inspect_configuration(self.store, item)
                        except Exception:
                            item = {"key": key, "source": "docker", "name": name}
                    message = f"{name}: {action}" + (f" (exit code {attrs['exitCode']})" if "exitCode" in attrs else "")
                    timestamp = datetime.fromtimestamp(event.get("time") or time.time(), timezone.utc).isoformat(timespec="seconds")
                    if self.store.add_event(event_key, "docker", key, action, message, "warning" if action in ("die", "oom", "kill") else "info", timestamp):
                        inspect_event(self.store, item, action, message, event_key)
                    if action in ("die", "stop", "destroy"):
                        self.store.set_state(key, "exited" if action != "destroy" else "deleted")
            except Exception as exc:
                log.debug("Docker event stream disconnected: %s", exc)
            finally:
                if client:
                    client.close()
            self.stop.wait(self.poll_seconds)

    def _kubernetes_client(self):
        from kubernetes import client, config
        if os.getenv("KUBERNETES_SERVICE_HOST"):
            config.load_incluster_config()
        else:
            config.load_kube_config()
        return client.CoreV1Api(), client.CustomObjectsApi()

    def _kubernetes_poll(self):
        while not self.stop.is_set():
            try:
                core, custom = self._kubernetes_client()
                pods = core.list_pod_for_all_namespaces(_request_timeout=10).items
                self.health["kubernetes"] = "connected"
                items = {}
                for pod in pods:
                    item = kubernetes_item(pod)
                    previous = self.store.container(item["key"])
                    self.store.upsert_container(item)
                    inspect_configuration(self.store, item)
                    self._scan_images(item)
                    items[(item["namespace"], item["name"])] = item
                    if previous and item["restarts"] > previous["restarts"]:
                        self.store.alert(f"{item['key']}:restarts", "kubernetes", item["key"], "restarts", "high",
                                         "Pod container restarted", f"{item['name']} restart count increased to {item['restarts']}.",
                                         "Inspect pod events and container logs.", 70, repeat=True)
                for event in core.list_event_for_all_namespaces(_request_timeout=10).items:
                    involved = event.involved_object
                    if not involved or involved.kind != "Pod" or not involved.uid:
                        continue
                    key = f"k8s:{involved.uid}"
                    item = items.get((involved.namespace, involved.name)) or self.store.container(key) or {
                        "key": key, "source": "kubernetes", "name": involved.name}
                    kind = event.reason or event.type or "Event"
                    message = f"{involved.name}: {kind}: {event.message or ''}"
                    event_key = f"k8s:{event.metadata.uid}:{event.count or 1}"
                    occurred = event.last_timestamp or event.event_time or event.metadata.creation_timestamp
                    occurred_at = occurred.isoformat() if occurred else None
                    severity = "warning" if event.type == "Warning" else "info"
                    if self.store.add_event(event_key, "kubernetes", key, kind, message, severity, occurred_at):
                        inspect_event(self.store, item, "warning" if severity == "warning" else kind, message, event_key)
                try:
                    metrics = custom.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods", _request_timeout=8)
                    for pod in metrics.get("items", []):
                        meta = pod.get("metadata", {})
                        item = items.get((meta.get("namespace"), meta.get("name")))
                        if not item:
                            continue
                        cpu = sum(quantity(c.get("usage", {}).get("cpu")) for c in pod.get("containers", [])) * 100
                        memory = int(sum(quantity(c.get("usage", {}).get("memory")) for c in pod.get("containers", [])))
                        inspect_sample(self.store, item, round(cpu, 2), memory)
                except Exception as exc:
                    log.debug("Kubernetes metrics unavailable (install metrics-server for usage charts): %s", exc)
            except Exception as exc:
                self.health["kubernetes"] = f"unavailable: {str(exc)[:100]}"
                log.debug("Kubernetes unavailable: %s", exc)
            self.stop.wait(self.poll_seconds)
