"""Bounded background Trivy scans, cached by immutable image reference."""
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)
DIGEST = re.compile(r"^(?:[A-Za-z0-9._:/-]+@)?sha256:[a-fA-F0-9]{64}$")


def images_for(item):
    images = item.get("details", {}).get("images", [])
    return images or [{"name": item["name"], "reference": item["image"], "digest": ""}]


def sanitize_report(report):
    """Allowlist metadata; never keep Trivy Match, Code, lines, or raw reports."""
    if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
        raise ValueError("Invalid Trivy report")
    findings = []
    for result in report.get("Results", []) or []:
        if not isinstance(result, dict):
            raise ValueError("Invalid Trivy result")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({"kind": "vulnerability", "target": result.get("Target", ""),
                             "id": vuln.get("VulnerabilityID", "unknown"), "package": vuln.get("PkgName", ""),
                             "installed_version": vuln.get("InstalledVersion", ""), "fixed_version": vuln.get("FixedVersion", ""),
                             "severity": str(vuln.get("Severity", "UNKNOWN")).lower(), "title": vuln.get("Title", "")})
        for secret in result.get("Secrets", []) or []:
            findings.append({"kind": "secret", "target": result.get("Target", ""),
                             "id": secret.get("RuleID", "unknown"), "severity": str(secret.get("Severity", "HIGH")).lower(),
                             "title": secret.get("Title", "Secret detected"), "value": "[REDACTED]"})
    counts = {level: sum(f["severity"] == level for f in findings)
              for level in ("critical", "high", "medium", "low", "unknown")}
    return {"findings": findings, "counts": counts, "total": len(findings)}


def run_trivy(image_ref):
    if not DIGEST.fullmatch(image_ref):
        raise ValueError("Scanning requires an immutable sha256 image reference")
    binary = shutil.which(os.getenv("SENTINEL_TRIVY_BINARY", "trivy"))
    if not binary:
        raise RuntimeError("Trivy is not installed; install the CLI or build the bundled Docker image")
    # Output can contain secrets. TemporaryDirectory cleans it on success AND failure.
    with tempfile.TemporaryDirectory(prefix="sentinel-trivy-") as directory:
        output = Path(directory) / "report.json"
        with (Path(directory) / "stderr.log").open("w+b") as stderr:
            completed = subprocess.run([binary, "image", "--quiet", "--skip-version-check",
                                        "--scanners", "vuln,secret", "--format", "json",
                                        "--timeout", "3m", "--output", str(output), "--", image_ref],
                                       stdout=subprocess.DEVNULL, stderr=stderr, timeout=200, check=False)
        if completed.returncode:
            # CLI stderr may echo credentials or secrets. Keep it out of DB/API/logs.
            raise RuntimeError(f"Trivy exited with code {completed.returncode}; check registry access and database connectivity")
        if not output.is_file() or output.stat().st_size > 50 * 1024 * 1024:
            raise RuntimeError("Trivy report is missing or exceeds the 50 MiB limit")
        return sanitize_report(json.loads(output.read_text(encoding="utf-8")))


class ImageScanner:
    def __init__(self, store):
        self.store = store
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="trivy")
        self.lock = threading.RLock()
        self.pending = {}  # image digest -> workload subscribers
        self.errors = {}
        self.retry_after = {}
        self.closed = False

    def close(self):
        with self.lock:
            self.closed = True
        self.executor.shutdown(wait=True, cancel_futures=True)

    def available(self):
        return bool(shutil.which(os.getenv("SENTINEL_TRIVY_BINARY", "trivy")))

    def results(self, item):
        output = []
        for image in images_for(item):
            ref = image.get("digest", "")
            scan = self.store.image_scan(ref) if ref else None
            with self.lock:
                status = "queued" if ref in self.pending else "error" if ref in self.errors else "complete" if scan else "not_scanned"
                error = self.errors.get(ref)
            if not DIGEST.fullmatch(ref):
                status, error = "unavailable", "Waiting for an immutable image ID from the container runtime"
            output.append({**image, "status": status, "error": error,
                           "scanned_at": scan["scanned_at"] if scan else None,
                           "result": scan["result"] if scan else None})
        return output

    def request(self, item, force=False):
        if not self.available():
            raise RuntimeError("Trivy is not installed; install the CLI or build the bundled Docker image")
        with self.lock:
            if self.closed:
                raise RuntimeError("Scanner is shutting down")
            for image in images_for(item):
                ref = image.get("digest", "")
                if not DIGEST.fullmatch(ref):
                    continue
                if ref in self.pending:
                    self.pending[ref].add(item["key"])
                    continue
                if not force and self.retry_after.get(ref, datetime.min.replace(tzinfo=timezone.utc)) > datetime.now(timezone.utc):
                    continue
                cached = self.store.image_scan(ref)
                if cached and not force and datetime.fromisoformat(cached["scanned_at"]) > datetime.now(timezone.utc) - timedelta(hours=24):
                    self._apply(item, ref, cached["result"])
                    continue
                if len(self.pending) >= 8:
                    raise RuntimeError("Scanner queue is full; retry after current jobs finish")
                self.errors.pop(ref, None)
                self.retry_after.pop(ref, None)
                self.pending[ref] = {item["key"]}
                self.executor.submit(self._scan, ref)
        return self.results(item)

    def _scan(self, ref):
        try:
            result = run_trivy(ref)
            previous = self.store.image_scan(ref)
            changed = bool(previous and previous["result"] != result)
            self.store.save_image_scan(ref, result)
            with self.lock:
                for key in self.pending[ref]:
                    item = self.store.container(key)
                    # Do not attach stale results after an image change.
                    if item and ref in {i.get("digest") for i in images_for(item)}:
                        self._apply(item, ref, result, changed=changed)
        except Exception as exc:
            message = str(exc) if isinstance(exc, RuntimeError) else "Image scan failed or timed out; retry the scan"
            with self.lock:
                self.errors[ref] = message
                self.retry_after[ref] = datetime.now(timezone.utc) + timedelta(minutes=5)
            log.warning("Image scan failed for %s (%s)", ref, type(exc).__name__)
        finally:
            with self.lock:
                self.pending.pop(ref, None)

    def _apply(self, item, ref, result, changed=False):
        fingerprint = f"{item['key']}:image_scan:{ref}"
        serious = [f for f in result["findings"] if f["severity"] in ("critical", "high") or f["kind"] == "secret"]
        if not serious:
            with self.store.connection() as db:
                db.execute("UPDATE alerts SET status='resolved' WHERE fingerprint=?", (fingerprint,))
            return
        severity = "critical" if any(f["severity"] == "critical" or f["kind"] == "secret" for f in serious) else "high"
        description = f"Image {ref} has {len(serious)} high/critical vulnerability or secret findings."
        self.store.alert(fingerprint, "trivy", item["key"], "image_scan", severity, "Image security findings", description,
                         "Update vulnerable packages or the base image; revoke detected secrets and rebuild the image without them.",
                         90 if severity == "critical" else 75, repeat=changed,
                         evidence={"image_ref": ref, "counts": result["counts"],
                                   "findings": serious[:30]})
