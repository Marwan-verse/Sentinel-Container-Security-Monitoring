from statistics import mean, pstdev


def _raise(store, item, rule, severity, title, detail, advice, score=0):
    store.alert(f"{item['key']}:{rule}", item["source"], item["key"], rule,
                severity, title, detail, advice, score)


def inspect_configuration(store, item):
    """Evaluate a normalized Docker container or Kubernetes pod."""
    details = item.get("details", {})
    key = item["key"]
    active = set()
    if details.get("privileged"):
        active.add("privileged")
        _raise(store, item, "privileged", "critical", "Privileged workload",
               f"{item['name']} can access privileged host capabilities.",
               "Remove privileged mode and grant only the capabilities the workload needs.", 95)
    if details.get("docker_socket"):
        active.add("docker_socket")
        _raise(store, item, "docker_socket", "critical", "Docker socket mounted",
               f"{item['name']} mounts the Docker Engine socket, which can control the host daemon.",
               "Remove the Docker socket mount and use a narrower integration.", 98)
    if details.get("host_pid"):
        active.add("host_pid")
        _raise(store, item, "host_pid", "high", "Host PID namespace",
               f"{item['name']} shares the host process namespace.",
               "Use an isolated PID namespace.", 80)
    if details.get("host_network"):
        active.add("host_network")
        _raise(store, item, "host_network", "high", "Host networking",
               f"{item['name']} shares the host network namespace.",
               "Use isolated container networking when possible.", 75)
    if details.get("host_path"):
        active.add("host_path")
        _raise(store, item, "host_path", "high", "Host path mounted",
               f"{item['name']} mounts a path from the host.",
               "Replace hostPath or bind mounts with a scoped volume.", 78)
    if details.get("root_user"):
        active.add("root_user")
        _raise(store, item, "root_user", "medium", "Runs as root",
               f"{item['name']} is configured to run as UID 0.",
               "Set a non-root user or runAsNonRoot security context.", 55)
    if details.get("allow_privilege_escalation"):
        active.add("privilege_escalation")
        _raise(store, item, "privilege_escalation", "medium", "Privilege escalation allowed",
               f"{item['name']} explicitly allows privilege escalation.",
               "Set allowPrivilegeEscalation to false.", 50)
    if details.get("dangerous_capabilities"):
        active.add("capabilities")
        capabilities = ", ".join(details["dangerous_capabilities"])
        _raise(store, item, "capabilities", "high", "Sensitive Linux capabilities",
               f"{item['name']} adds {capabilities}.",
               "Drop added capabilities unless a documented requirement exists.", 80)
    store.resolve_configuration(key, active)


def inspect_event(store, item, kind, message, event_key):
    source, key = item["source"], item["key"]
    rule = None
    severity = "medium"
    advice = "Inspect the workload events and application logs."
    kind_lower = kind.lower()
    message_lower = message.lower()
    if "oom" in kind_lower or "oomkill" in message_lower:
        rule, severity = "oom", "high"
        advice = "Check memory usage, limits, and recent workload changes."
    elif "backoff" in kind_lower or "backoff" in message_lower or "crashloop" in message_lower:
        rule, severity = "crash_loop", "high"
        advice = "Inspect container logs, probes, and image configuration."
    elif kind_lower in ("die", "kill"):
        rule = "unexpected_exit"
        advice = "Check the exit code and events around the shutdown."
    elif kind_lower == "warning":
        rule = "kubernetes_warning"
    if rule:
        store.alert(f"{key}:{rule}", source, key, rule, severity,
                    {"oom": "Out of memory", "crash_loop": "Repeated start failure",
                     "unexpected_exit": "Container stopped", "kubernetes_warning": "Kubernetes warning"}[rule],
                    message, advice, 75 if severity == "high" else 45, repeat=True)


def inspect_sample(store, item, cpu, memory):
    """Compare a new sample with the previous 30 samples, then persist it."""
    history = store.recent_samples(item["key"], 30)
    for metric, value, minimum_jump, label in (
        ("cpu_percent", cpu, 20, "CPU"),
        ("memory_bytes", memory, 64 * 1024 * 1024, "Memory"),
    ):
        values = [float(x[metric]) for x in history if x[metric] is not None]
        if value is None or len(values) < 8:
            continue
        average = mean(values)
        deviation = pstdev(values)
        jump = float(value) - average
        if jump >= minimum_jump and jump >= 3 * max(deviation, 1) and value >= 1.5 * max(average, 1):
            score = min(100, round(65 + 5 * jump / max(deviation, 1)))
            unit = "%" if metric == "cpu_percent" else " MiB"
            shown = round(value, 1) if metric == "cpu_percent" else round(value / 1048576, 1)
            baseline = round(average, 1) if metric == "cpu_percent" else round(average / 1048576, 1)
            store.alert(f"{item['key']}:{metric}_anomaly", item["source"], item["key"],
                        f"{metric}_anomaly", "high", f"Unusual {label.lower()} usage",
                        f"{label} reached {shown}{unit} versus a recent average of {baseline}{unit}.",
                        "Compare recent events and workload changes with this resource spike.", score, repeat=True)
    store.add_sample(item["key"], cpu, memory)
