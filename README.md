# Sentinel container monitor

A small Docker and Kubernetes security monitor with a React dashboard. It stores workload inventory, runtime events, resource samples, and correlated alerts in SQLite. Configuration rules flag privileged workloads, root users, host namespace access, host mounts, Docker socket mounts, privilege escalation, and sensitive capabilities. Resource alerts compare current usage with a rolling baseline of previous samples.

## Quick start without Docker or Kubernetes

Requires Python 3.11+ and Node.js 20+.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
.\.venv\Scripts\python -m sentinel.demo
$env:SENTINEL_MODE = "off"
.\.venv\Scripts\python -m uvicorn sentinel.api:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The API docs are at <http://127.0.0.1:8000/docs>. `SENTINEL_MODE=off` shows the seeded data without attempting collector connections.

On macOS or Linux, use `source .venv/bin/activate` and run `python` instead of `.\.venv\Scripts\python`.

## Monitor a local Docker Engine

With Docker installed and running:

```bash
docker compose up --build -d
```

Open <http://127.0.0.1:8000>. The Compose collector runs as root to access the mounted Docker Engine socket. **Access to this socket effectively grants control of the Docker host**, even when the socket mount is marked read-only. Use this on a machine you trust and keep the dashboard on localhost. The app has no login system.

Start the opt-in lab containers in a disposable environment:

```bash
docker compose -f lab/compose.yaml up -d
```

The `insecure-demo` container runs as root with privileged mode and `NET_ADMIN`. It has no published ports or host mounts. `crash-demo` exits intentionally so the monitor records an exit event. Remove the lab with `docker compose -f lab/compose.yaml down`.

## Monitor Kubernetes

Build the image and make it available to your cluster. For a local kind cluster:

```bash
docker build -t sentinel-monitor:local .
kind load docker-image sentinel-monitor:local
kubectl apply -f k8s/monitor.yaml
kubectl -n sentinel-system port-forward service/sentinel-monitor 8000:8000
```

Open <http://127.0.0.1:8000>. For minikube, use `minikube image load sentinel-monitor:local` instead of `kind load`. For a remote cluster, push the image to a registry and change the image in `k8s/monitor.yaml` before applying it. The manifest creates a read-only ClusterRole for pod and event inspection, a persistent volume claim for SQLite, and a ClusterIP service. It expects a default StorageClass; if your cluster has none, provision a suitable persistent volume or change the claim.

Kubernetes CPU and memory data requires the `metrics.k8s.io` API, commonly provided by Metrics Server. Pods, configuration findings, and events still work when metrics are unavailable. The collector reads all namespaces. Kubernetes CPU is shown as a percent of one core; values can exceed 100%.

Start the Kubernetes lab **only in a disposable test cluster**:

```bash
kubectl apply -f lab/kubernetes.yaml
```

The lab creates a `sentinel-lab` namespace with Pod Security enforcement set to `privileged`, a privileged root pod, and a pod that intentionally crash loops. This weakens admission controls for that lab namespace. Clean up with `kubectl delete -f lab/kubernetes.yaml`.

## Use the dashboard

- **Single page:** workload and alert counts, current findings, workload inventory, and recent events. Data refreshes every five seconds.
- **Alerts:** rule explanations, recommendations, severity, acknowledgement, and resolution. The first three appear by default; use **Show all** to expand the list.
- **Workload details:** current CPU and memory use, configuration, findings, and recent events for a Docker container or Kubernetes pod.
- **Export report:** downloads a Markdown incident report of open findings and recent events.
- **Explain with AI:** when `OPENAI_API_KEY` is set, an alert can be explained on demand using the OpenAI Responses API. Only the chosen alert, workload name, and up to eight recent event messages are sent; the response is not stored in SQLite.

Open alerts are correlated by workload and rule. The count grows when a matching runtime event repeats. Configuration findings remain a single alert across polls. Resource anomalies require at least eight previous samples and a significant jump over the rolling mean and standard deviation.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
cd frontend && npm install && npm run build
```

For frontend development, run `npm run dev` from `frontend/` and run the FastAPI server on port 8000. Vite proxies `/api` requests to it.

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SENTINEL_MODE` | `auto` | `docker`, `kubernetes`, `all`, `auto`, or `off` |
| `SENTINEL_DB` | `data/sentinel.db` | SQLite database path |
| `SENTINEL_POLL_SECONDS` | `10` | Collector polling interval, minimum 5 seconds |
| `OPENAI_API_KEY` | unset | Enables the optional AI explanation button |
| `OPENAI_MODEL` | `gpt-5-mini` | Model used for optional explanations |

The current design runs one API process and one SQLite writer per deployment. Run a single Uvicorn worker and one Kubernetes replica. The dashboard is intended for local or port-forwarded use; add authentication and a more scalable data store before exposing it to other users.
