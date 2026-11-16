"""Accept Falco JSON alerts without persisting raw outputs or command arguments."""
import hashlib
import json
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class FalcoEvent(BaseModel):
    rule: str = Field(min_length=1, max_length=200)
    priority: str = Field(min_length=1, max_length=30)
    time: str = Field(min_length=1, max_length=80)
    output_fields: dict = Field(default_factory=dict)


PRIORITIES = {"emergency": "critical", "alert": "critical", "critical": "critical",
              "error": "high", "warning": "high", "notice": "medium",
              "informational": "low", "info": "low", "debug": "low"}
SAFE_FIELDS = {"container.id", "container.name", "proc.name", "proc.exepath",
               "evt.type", "fd.name", "user.uid", "k8s.ns.name", "k8s.pod.name"}


def ingest(store, event):
    priority = event.priority.lower()
    if priority not in PRIORITIES:
        raise ValueError("Unknown Falco priority")
    try:
        timestamp = datetime.fromisoformat(event.time.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError()
        occurred_at = timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except ValueError as exc:
        raise ValueError("Falco time must be an ISO-8601 timestamp with timezone") from exc
    ident = event.output_fields.get("container.id")
    if not isinstance(ident, str) or not ident or ident == "host":
        raise ValueError("A container.id is required; host events are not accepted")
    workload = store.runtime_workload(ident)
    if not workload:
        raise ValueError("Container is unknown or ambiguous; wait for inventory collection and retry")
    fields = {key: str(value)[:1024] for key, value in event.output_fields.items()
              if key in SAFE_FIELDS and isinstance(value, (str, int, float, bool))}
    # Hash the original event (including nanoseconds) for exact delivery deduplication.
    fingerprint = hashlib.sha256(json.dumps(event.model_dump(), sort_keys=True).encode()).hexdigest()
    severity = PRIORITIES[priority]
    title = f"Falco: {event.rule}"
    evidence = {"provider": "falco", "fields": fields, "event_time": event.time}
    message = f"{workload['name']}: {event.rule}"
    accepted = store.add_runtime_event(f"falco:{fingerprint}", workload, event.rule, title,
                                       message, severity, occurred_at, evidence)
    return {"accepted": accepted, "duplicate": not accepted, "container_key": workload["key"]}
