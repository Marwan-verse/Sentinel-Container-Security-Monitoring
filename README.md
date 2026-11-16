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

## Runtime detection with Falco

Sentinel accepts container alerts from [Falco](https://falco.org/docs/), so shell execution, sensitive file writes, and other process activity can be investigated alongside configuration findings. Falco must run on the monitored **Linux host or Kubernetes nodes** with rules enabled for the activity you want to detect. Installing Sentinel alone does not install a kernel sensor. On Windows, run the sensor in the monitored Linux environment.

1. Configure a strong random `SENTINEL_FALCO_TOKEN` in the monitor environment. Compose passes this variable through; keep it in an untracked `.env` or your process environment. Restart the monitor after changing its environment.
2. Enable Falco JSON output. Forward one event per request to `POST /api/runtime/falco` with `Authorization: Bearer <token>`.
3. The included relay can forward Falco stdout. In the Python environment containing Sentinel and with the same token set, run on the Linux sensor host:

   ```bash
   sudo falco -o json_output=true | python -m sentinel.forward_falco
   ```

   Set `SENTINEL_FALCO_URL` if the monitor is elsewhere; use a trusted TLS endpoint for remote forwarding. The relay retries each delivery up to six times, then reports failure without printing its contents. It is not a durable event queue; use a persistent forwarding service if delivery guarantees are needed.

For Kubernetes, create an optional `sentinel-falco` Secret in `sentinel-system` with a `token` key before restarting the Deployment. The manifest reads this key without requiring a Secret for installations that do not use Falco. Forward from the node sensor or a relay that supplies the bearer header to `http://sentinel-monitor.sentinel-system:8000/api/runtime/falco` within the trusted cluster network. Do not place tokens in committed YAML.

Required JSON fields are `rule`, `priority`, `time` (ISO-8601 with timezone), and `output_fields.container.id`. A minimal event looks like:

```json
{
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "time": "2026-11-16T12:00:00.123456789Z",
  "output_fields": {
    "container.id": "0123456789ab",
    "proc.name": "sh",
    "evt.type": "execve"
  }
}
```

Use an actual inventoried container ID. Sentinel matches full IDs or unique prefixes of at least 12 characters, including Kubernetes runtime container IDs. Unknown, ambiguous, and host-only events are rejected with 422 so senders can retry after inventory collection. Repeated deliveries are deduplicated transactionally. Requests are limited to 256 KiB; the endpoint returns 503 when disabled and 401 for a bad token. Only allowlisted process/file metadata is persisted: raw output, command arguments, and arbitrary output fields are discarded. File paths and process names may still be sensitive.

## Incident investigations

The **Incidents** section opens an evidence timeline containing configuration changes, Falco activity, resource anomalies, and image findings. Different rules for the same workload join an incident while its last new signal is within a 30-minute ingestion-time idle window. After that window, or after manual resolution, the next new signal starts a new incident. Unchanged configuration polling and unchanged cached scan findings do not add timeline entries.

Each entry keeps an immutable copy of its evidence and recommendation. Runtime timestamps are shown separately from reception time in the evidence API. A shared workload/time window indicates correlation, not proof of an attack or causal order. Acknowledge, resolve, and reopen incidents independently of individual alert statuses; resolving an incident does not resolve its underlying findings. Timelines can load earlier signals. Existing active alerts are imported once when an older database is opened.

## Image vulnerability and secret scanning

Open a workload and choose **Scan images with Trivy**. The Docker image includes Trivy 0.76.2. For a native Python deployment, install the [Trivy CLI](https://trivy.dev/docs/latest/getting-started/installation/) on PATH, or set `SENTINEL_TRIVY_BINARY` to its executable path. No scanner installation or image download occurs merely by starting the dashboard.

- Scans run in one background worker, with at most eight distinct queued image IDs. The dashboard remains available while scans run. Scan failures are displayed per image; automatic retries back off for five minutes.
- Only immutable SHA-256 image IDs/digests discovered from inventory are scanned. Mutable tags without a resolved ID display **unavailable** until the runtime provides one. Docker scans use the local image ID; Kubernetes scans use the runtime image reference. Private registries require Trivy's registry credentials in the monitor environment. A node-local ID inaccessible to Trivy may require registry access to a pullable digest.
- Successful results are cached in SQLite by immutable reference for 24 hours and shared across workloads. The button forces a refresh. Set `SENTINEL_SCAN_IMAGES=true` to also scan discovered images automatically (off by default).
- Results include vulnerability IDs, installed/fixed package versions, severity counts, and secret detection locations. Secret values, matching lines, and code excerpts are excluded from database/API/incident evidence. Raw reports exist only in a temporary directory during parsing and are removed on success or failure.
- High/critical vulnerabilities or detected secrets create an image alert and incident evidence. Clean rescans resolve that image alert; replacing the image resolves findings attached to the old image. A scan failure preserves the previous successful report and labels the current attempt as failed.
- Trivy needs network access for its vulnerability databases and remote images. Compose and Kubernetes persist its cache at `/data/trivy-cache`. Monitor disk and memory capacity when scanning large images; the API accepts reports up to 50 MiB.

## Configuration history

Workload details show the initial configuration snapshot and subsequent field-by-field before/after changes, including images/digests, privilege settings, mounts, capabilities, and Kubernetes service accounts/container security contexts. Identical polls, changed resource samples, runtime container IDs, and pod IP changes do not create snapshots. Snapshot changes also appear as incident signals and recent events.

History is scoped to a Docker container ID or Kubernetes Pod UID. Replacing a container or Pod creates a new workload; cross-revision Deployment/Compose-service history is not inferred. Earlier snapshots can be loaded in the UI. The schema is extended automatically without deleting existing records; back up the SQLite database before upgrading. History, events, and incident evidence are retained until the database is archived or managed by the operator.

New API routes (also visible in `/docs`):

| Route | Purpose |
| --- | --- |
| `POST /api/runtime/falco` | Authenticated Falco ingestion |
| `GET /api/incidents?status=open&key=...` | List/filter investigations |
| `GET /api/incidents/{id}?limit=200&before=...` | Timeline page and `next_before` cursor |
| `POST /api/incidents/{id}/status?status=resolved` | Update investigation status |
| `GET /api/history/{workload-key}?limit=50&before=...` | Configuration snapshot page |
| `POST /api/scans/{workload-key}?force=true` | Queue image scans (202) |

`GET /api/containers/{workload-key}` also includes history, related incidents, and current image scan results. History pages are newest-first; pass the oldest entry ID as `before`. The original dashboard/API access model still applies: keep it local or port-forwarded unless you add authentication and authorization. The Falco token only protects its ingestion endpoint.

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
| `SENTINEL_FALCO_TOKEN` | unset | Enables bearer-authenticated Falco ingestion |
| `SENTINEL_FALCO_URL` | `http://127.0.0.1:8000/api/runtime/falco` | Destination used by the optional relay |
| `SENTINEL_SCAN_IMAGES` | `false` | Automatically queue discovered immutable images |
| `SENTINEL_TRIVY_BINARY` | `trivy` | Trivy executable name or absolute path |
| `TRIVY_CACHE_DIR` | Trivy default | Downloaded scanner databases/cache; `/data/trivy-cache` in manifests |
| `OPENAI_API_KEY` | unset | Enables the optional AI explanation button |
| `OPENAI_MODEL` | `gpt-5-mini` | Model used for optional explanations |

The current design runs one API process and one SQLite writer per deployment. Run a single Uvicorn worker and one Kubernetes replica. The dashboard is intended for local or port-forwarded use; add authentication and a more scalable data store before exposing it to other users.
