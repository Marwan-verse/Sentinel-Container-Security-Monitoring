import React, { useEffect, useState } from 'react'

const time = value => value ? new Date(value).toLocaleString() : '—'
const display = value => value == null ? '(unset)' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const mergeTimeline = (...pages) => [...new Map(pages.flat().map(entry => [entry.id, entry])).values()]
  .sort((a, b) => a.occurred_at.localeCompare(b.occurred_at) || a.id - b.id)

export function IncidentPanel({ incidents, api, updatedAt, refresh, search, showResolved }) {
  const [selected, setSelected] = useState(null)
  const [incident, setIncident] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    if (!selected) { setIncident(null); return }
    let active = true
    api(`/incidents/${selected}`).then(result => {
      if (active) {
        setIncident(previous => {
          if (previous?.id !== result.id || previous.timeline.length <= result.timeline.length) return result
          return { ...result, timeline: mergeTimeline(previous.timeline, result.timeline), next_before: previous.next_before }
        })
        setError('')
      }
    }).catch(reason => { if (active) setError(reason.message) })
    const onKey = event => { if (event.key === 'Escape') setSelected(null) }
    window.addEventListener('keydown', onKey)
    return () => { active = false; window.removeEventListener('keydown', onKey) }
  }, [selected, updatedAt])

  async function status(value) {
    try { await api(`/incidents/${selected}/status?status=${value}`, { method: 'POST' }); await refresh() }
    catch (reason) { setError(reason.message) }
  }
  async function earlier() {
    setLoading(true)
    try {
      const page = await api(`/incidents/${selected}?before=${incident.next_before}`)
      setIncident(previous => previous?.id === selected ? { ...previous, timeline: mergeTimeline(page.timeline, previous.timeline), next_before: page.next_before } : previous)
    } catch (reason) { setError(reason.message) }
    finally { setLoading(false) }
  }
  const visible = incidents.filter(item => (showResolved || item.status !== 'resolved') &&
    `${item.title} ${item.container_key} ${item.severity}`.toLowerCase().includes(search))
  return <>
    <section className="section" aria-labelledby="incidents-title">
      <div className="section-heading"><div><h2 id="incidents-title">Incidents</h2><p>Related signals grouped by workload within a 30-minute activity window</p></div></div>
      {visible.length ? <div className="list">{visible.map(item => <article className="alert" key={item.id}>
        <div className="alert-heading"><span className={`badge ${item.severity}`}>{item.severity}</span><h3>{item.title}</h3><span className="badge">{item.status}</span></div>
        <p className="meta">{item.signal_count} signals · {time(item.first_seen)} – {time(item.last_seen)}</p>
        <div className="actions"><button className="text-button" onClick={() => { setIncident(null); setSelected(item.id) }}>Investigate</button></div>
      </article>)}</div> : <div className="empty">No incidents to show.</div>}
    </section>
    {selected && <div className="modal-backdrop" onClick={() => setSelected(null)}>
      <div className="modal incident-modal" role="dialog" aria-modal="true" aria-label="Incident investigation" onClick={event => event.stopPropagation()}>
        <button className="close-button" aria-label="Close incident" onClick={() => setSelected(null)}>×</button>
        {error && <p className="error" role="alert">{error}</p>}
        {incident ? <><h2>{incident.title}</h2><p className="meta">{incident.container_key}</p>
          <p className="muted">Signals share a workload and time window. This relationship does not establish an attack or causation.</p>
          <div className="actions">{['open', 'acknowledged', 'resolved'].filter(value => value !== incident.status).map(value =>
            <button className="text-button" key={value} onClick={() => status(value)}>{value === 'open' ? 'Reopen' : value === 'acknowledged' ? 'Acknowledge' : 'Resolve'} incident</button>)}</div>
          <h3>Evidence timeline</h3>
          {incident.next_before && <button className="text-button" disabled={loading} onClick={earlier}>{loading ? 'Loading…' : 'Load earlier signals'}</button>}
          <ol className="timeline">{incident.timeline.map(entry => <li key={entry.id}>
            <div className="alert-heading"><span className={`badge ${entry.severity}`}>{entry.severity}</span><strong>{entry.title}</strong></div>
            <p className="meta">{time(entry.occurred_at)} · {entry.kind}</p>
            {entry.evidence.description && <p>{entry.evidence.description}</p>}
            {entry.evidence.recommendation && <p><strong>What to do:</strong> {entry.evidence.recommendation}</p>}
            <details><summary>View evidence</summary><pre className="evidence">{JSON.stringify(entry.evidence, null, 2)}</pre></details>
          </li>)}</ol>
        </> : <p>Loading incident…</p>}
      </div>
    </div>}
  </>
}

export function WorkloadSecurity({ detail, api, refresh, scannerAvailable }) {
  const [error, setError] = useState('')
  const [scanning, setScanning] = useState(false)
  const [older, setOlder] = useState([])
  const [loadingHistory, setLoadingHistory] = useState(false)
  const [historyDone, setHistoryDone] = useState(false)
  const [findingsLimit, setFindingsLimit] = useState(30)
  useEffect(() => { setOlder([]); setHistoryDone(false) }, [detail.key])
  async function scan() {
    setScanning(true); setError('')
    try { await api(`/scans/${encodeURIComponent(detail.key)}?force=true`, { method: 'POST' }); await refresh() }
    catch (reason) { setError(reason.message) }
    finally { setScanning(false) }
  }
  const history = [...detail.history, ...older].filter((entry, index, entries) => entries.findIndex(other => other.id === entry.id) === index)
  async function loadHistory() {
    setLoadingHistory(true)
    try {
      const page = await api(`/history/${encodeURIComponent(detail.key)}?before=${history.at(-1).id}`)
      setOlder(previous => [...previous, ...page]); setHistoryDone(page.length < 50)
    } catch (reason) { setError(reason.message) }
    finally { setLoadingHistory(false) }
  }
  return <>
    <h3>Image security</h3>
    {!scannerAvailable && <p className="muted">Trivy is not installed on the monitor. Use the bundled Docker image or install the Trivy CLI to enable scanning.</p>}
    <button className="button secondary" disabled={!scannerAvailable || scanning || detail.image_scans.some(image => image.status === 'queued')} onClick={scan}>
      {scanning || detail.image_scans.some(image => image.status === 'queued') ? 'Scan queued…' : 'Scan images with Trivy'}
    </button>
    {error && <p className="error" role="alert">{error}</p>}
    {detail.image_scans.map((image, index) => <div className="scan-result" key={`${image.name}-${index}`}>
      <strong>{image.name}</strong><p className="meta">{image.reference}</p>
      <p className="image-name">{image.digest || 'No immutable image ID yet'}</p>
      <span className="badge">{image.status.replaceAll('_', ' ')}</span>
      {image.error && <p className="muted">{image.error}</p>}
      {image.result && <><p className="muted">Last scanned {time(image.scanned_at)} · {image.result.total} findings</p>
        <div className="actions">{Object.entries(image.result.counts).map(([level, count]) => <span className={`badge ${level}`} key={level}>{count} {level}</span>)}</div>
        <details><summary>Vulnerabilities and secrets</summary>
          {image.result.findings.slice(0, findingsLimit).map((finding, number) => <div className="finding" key={number}>
            <span className={`badge ${finding.severity}`}>{finding.severity}</span> <strong>{finding.id}</strong>
            <p>{finding.package || finding.title} {finding.installed_version || ''}</p>
            <p className="meta">{finding.target}</p>
            <p>{finding.kind === 'secret' ? 'Secret value redacted. Revoke and remove it from the image.' : `Fixed version: ${finding.fixed_version || 'No fix listed'}`}</p>
          </div>)}
          {image.result.total > findingsLimit && <button className="text-button" onClick={() => setFindingsLimit(value => value + 30)}>Show more findings</button>}
          {!image.result.total && <p className="muted">No findings in this scan.</p>}
        </details>
      </>}
    </div>)}
    <h3>Configuration history</h3>
    <p className="muted">Snapshots are recorded when settings change. The first observation is the baseline.</p>
    {history.map(entry => <details className="history-entry" key={entry.id}>
      <summary>{time(entry.observed_at)} · {entry.changes.length ? `${entry.changes.length} changes` : 'Initial snapshot'}</summary>
      {entry.changes.map(change => <div className="config-diff" key={change.field}><strong>{change.field}</strong>
        <del>{display(change.before)}</del><ins>{display(change.after)}</ins></div>)}
      <details><summary>Full snapshot</summary><pre className="evidence">{JSON.stringify(entry.snapshot, null, 2)}</pre></details>
    </details>)}
    {!history.length && <p className="muted">Waiting for the next inventory collection.</p>}
    {!historyDone && history.length >= 50 && <button className="text-button" disabled={loadingHistory} onClick={loadHistory}>{loadingHistory ? 'Loading…' : 'Load earlier snapshots'}</button>}
  </>
}
