import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './style.css'

const formatTime = value => value ? new Date(value).toLocaleString() : '—'
const formatMemory = value => value == null ? '—' : `${(value / 1048576).toFixed(1)} MiB`
const formatCpu = value => value == null ? '—' : `${value.toFixed(1)}%`
const alertPreviewCount = 3

async function api(path, options) {
  const response = await fetch(`/api${path}`, options)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `${response.status} ${response.statusText}`)
  }
  return response.json()
}

function Badge({ children, kind = '' }) {
  return <span className={`badge ${kind}`}>{children}</span>
}

function App() {
  const [summary, setSummary] = useState(null)
  const [health, setHealth] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [containers, setContainers] = useState([])
  const [events, setEvents] = useState([])
  const [query, setQuery] = useState('')
  const [showResolved, setShowResolved] = useState(false)
  const [showAllAlerts, setShowAllAlerts] = useState(false)
  const [selectedKey, setSelectedKey] = useState(null)
  const [detail, setDetail] = useState(null)
  const [explanations, setExplanations] = useState({})
  const [explaining, setExplaining] = useState(null)
  const [updatedAt, setUpdatedAt] = useState(null)
  const [error, setError] = useState('')

  async function refresh() {
    try {
      const [nextSummary, nextHealth, nextAlerts, nextContainers, nextEvents] = await Promise.all([
        api('/summary'), api('/health'), api('/alerts'), api('/containers'), api('/events')
      ])
      setSummary(nextSummary)
      setHealth(nextHealth)
      setAlerts(nextAlerts)
      setContainers(nextContainers)
      setEvents(nextEvents)
      setUpdatedAt(new Date())
      setError('')
    } catch (reason) {
      setError(`Could not load monitoring data: ${reason.message}`)
    }
  }

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (!selectedKey) {
      setDetail(null)
      return
    }
    let active = true
    api(`/containers/${encodeURIComponent(selectedKey)}`)
      .then(value => { if (active) setDetail(value) })
      .catch(reason => { if (active) setError(`Could not load workload: ${reason.message}`) })
    return () => { active = false }
  }, [selectedKey, updatedAt])

  useEffect(() => {
    if (!selectedKey) return
    function onKeyDown(event) {
      if (event.key === 'Escape') setSelectedKey(null)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [selectedKey])

  async function changeStatus(id, status) {
    try {
      await api(`/alerts/${id}/status?status=${status}`, { method: 'POST' })
      await refresh()
    } catch (reason) {
      setError(`Could not update alert: ${reason.message}`)
    }
  }

  async function explainAlert(id) {
    setExplaining(id)
    try {
      const result = await api(`/alerts/${id}/explain`, { method: 'POST' })
      setExplanations(previous => ({ ...previous, [id]: result.explanation }))
    } catch (reason) {
      setError(`Could not explain alert: ${reason.message}`)
    } finally {
      setExplaining(null)
    }
  }

  async function downloadReport() {
    try {
      const response = await fetch('/api/reports/incident')
      if (!response.ok) throw new Error(response.statusText)
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = `sentinel-incident-${new Date().toISOString().slice(0, 10)}.md`
      link.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (reason) {
      setError(`Could not download report: ${reason.message}`)
    }
  }

  const search = query.trim().toLowerCase()
  const matchingAlerts = alerts.filter(alert =>
    (showResolved || alert.status !== 'resolved') &&
    `${alert.title} ${alert.description} ${alert.container_key}`.toLowerCase().includes(search)
  )
  const visibleAlerts = showAllAlerts ? matchingAlerts : matchingAlerts.slice(0, alertPreviewCount)
  const matchingContainers = containers.filter(container =>
    `${container.name} ${container.namespace} ${container.image} ${container.source}`.toLowerCase().includes(search)
  )
  const connected = Object.entries(health?.collectors || {})
    .filter(([, status]) => status === 'connected')
    .map(([source]) => source === 'docker' ? 'Docker' : 'Kubernetes')

  return <div className="app">
    <header className="site-header">
      <div className="header-inner">
        <div className="brand"><span className="brand-icon">S</span><strong>Sentinel</strong></div>
        <button className="button secondary" onClick={downloadReport}>Download report</button>
      </div>
    </header>

    <main className="page">
      <div className="intro">
        <h1>Container security monitor</h1>
        <p>See risky settings and unusual activity across Docker and Kubernetes.</p>
      </div>

      <div className="status-line">
        <span className="live-indicator" />
        {health?.mode === 'off' ? 'Demo data' : connected.length ? `Connected to ${connected.join(' and ')}` : 'Waiting for collectors'}
        <span className="status-separator">·</span>
        Updated {updatedAt ? updatedAt.toLocaleTimeString() : '—'}
      </div>

      {error && <div className="error" role="alert">{error}</div>}

      <div className="summary" aria-label="Monitoring summary">
        <div><strong>{summary?.containers ?? '—'}</strong><span>workloads</span></div>
        <div><strong>{summary?.open_alerts ?? '—'}</strong><span>open alerts</span></div>
        <div><strong>{summary?.critical_alerts ?? '—'}</strong><span>critical</span></div>
      </div>

      <div className="search-row">
        <label htmlFor="search">Search</label>
        <input id="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Find an alert or workload" />
      </div>

      <section className="section" aria-labelledby="alerts-title">
        <div className="section-heading">
          <div><h2 id="alerts-title">Alerts</h2><p>What needs attention</p></div>
          <label className="checkbox"><input type="checkbox" checked={showResolved} onChange={event => setShowResolved(event.target.checked)} /> Show resolved</label>
        </div>

        {visibleAlerts.length ? <div className="list">
          {visibleAlerts.map(alert => <article className="alert" key={alert.id}>
            <div className="alert-heading">
              <Badge kind={alert.severity}>{alert.severity}</Badge>
              <h3>{alert.title}</h3>
              {alert.status !== 'open' && <Badge>{alert.status}</Badge>}
            </div>
            <div className="meta">{alert.container_key || 'Unknown workload'} · {formatTime(alert.last_seen)}</div>
            <p>{alert.description}</p>
            <p className="advice"><strong>What to do:</strong> {alert.recommendation}</p>
            {explanations[alert.id] && <div className="explanation"><strong>AI explanation</strong><p>{explanations[alert.id]}</p></div>}
            <div className="actions">
              {alert.container_key && <button className="text-button" onClick={() => setSelectedKey(alert.container_key)}>View workload</button>}
              {health?.ai_enabled && <button className="text-button" disabled={explaining === alert.id} onClick={() => explainAlert(alert.id)}>{explaining === alert.id ? 'Explaining…' : 'Explain with AI'}</button>}
              {alert.status === 'open' && <button className="text-button" onClick={() => changeStatus(alert.id, 'acknowledged')}>Acknowledge</button>}
              {alert.status !== 'resolved' && <button className="text-button" onClick={() => changeStatus(alert.id, 'resolved')}>Resolve</button>}
              {alert.status === 'resolved' && <button className="text-button" onClick={() => changeStatus(alert.id, 'open')}>Reopen</button>}
            </div>
          </article>)}
        </div> : <div className="empty">No alerts to show.</div>}
        {matchingAlerts.length > alertPreviewCount && <button className="show-more" onClick={() => setShowAllAlerts(!showAllAlerts)}>{showAllAlerts ? 'Show fewer alerts' : `Show all ${matchingAlerts.length} alerts`}</button>}
      </section>

      <section className="section" aria-labelledby="workloads-title">
        <div className="section-heading"><div><h2 id="workloads-title">Workloads</h2><p>Docker containers and Kubernetes pods</p></div></div>
        {matchingContainers.length ? <div className="list">
          {matchingContainers.map(container => <div className="workload" key={container.key}>
            <div className="workload-main"><strong>{container.name}</strong><span>{container.source === 'docker' ? 'Docker' : `Kubernetes · ${container.namespace}`} · {container.state}</span></div>
            <div className="workload-usage">CPU {formatCpu(container.cpu_percent)} <span>·</span> Memory {formatMemory(container.memory_bytes)}</div>
            <button className="text-button" onClick={() => setSelectedKey(container.key)}>Details</button>
          </div>)}
        </div> : <div className="empty">No workloads to show.</div>}
      </section>

      <section className="section" aria-labelledby="events-title">
        <div className="section-heading"><div><h2 id="events-title">Recent events</h2><p>Latest container activity</p></div></div>
        {events.length ? <div className="list">
          {events.slice(0, 8).map(event => <div className="event" key={event.id}>
            <div><strong>{event.message}</strong><span>{event.source} · {event.kind}</span></div>
            <time>{formatTime(event.occurred_at)}</time>
          </div>)}
        </div> : <div className="empty">No events yet.</div>}
      </section>
    </main>

    {selectedKey && <div className="modal-backdrop" onClick={() => setSelectedKey(null)}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Workload details" onClick={event => event.stopPropagation()}>
        <button className="close-button" aria-label="Close details" onClick={() => setSelectedKey(null)}>×</button>
        {detail ? <>
          <h2>{detail.name}</h2>
          <p className="meta">{detail.source === 'docker' ? 'Docker' : `Kubernetes · ${detail.namespace}`} · {detail.state}</p>
          <p className="image-name">{detail.image}</p>
          <div className="detail-metrics"><span>CPU <strong>{formatCpu(detail.cpu_percent)}</strong></span><span>Memory <strong>{formatMemory(detail.memory_bytes)}</strong></span><span>Restarts <strong>{detail.restarts}</strong></span></div>
          <h3>Findings</h3>
          {detail.alerts.length ? detail.alerts.map(alert => <div className="detail-line" key={alert.id}><Badge kind={alert.severity}>{alert.severity}</Badge><span>{alert.title}</span></div>) : <p className="muted">No findings.</p>}
          <h3>Configuration</h3>
          <div className="configuration">{Object.entries(detail.details).map(([key, value]) => <div key={key}><span>{key.replaceAll('_', ' ')}</span><strong>{typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')}</strong></div>)}</div>
          <h3>Recent events</h3>
          {detail.events.length ? detail.events.slice(0, 6).map(event => <p className="detail-event" key={event.id}>{event.message}</p>) : <p className="muted">No recent events.</p>}
        </> : <p>Loading workload…</p>}
      </div>
    </div>}
  </div>
}

createRoot(document.getElementById('root')).render(<App />)
