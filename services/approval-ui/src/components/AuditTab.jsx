import { useCallback, useEffect, useState } from 'react'
import { ApiError, listAudit } from '../api/client.js'

function formatTime(value) {
  if (!value) {
    return ''
  }
  return new Date(value).toLocaleString()
}

function formatMetadata(metadata) {
  try {
    return JSON.stringify(metadata || {})
  } catch {
    return '{}'
  }
}

export function AuditTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [events, setEvents] = useState([])

  const loadAudit = useCallback(async () => {
    onStatus('Loading audit log…')
    try {
      const items = await listAudit()
      setEvents(items)
      onStatus(`${items.length} event(s) loaded.`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load audit log', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadAudit()
    }
  }, [active, loadAudit, refreshToken])

  return (
    <section className="panel">
      <div className="panel-head">Audit log (latest 100 events)</div>
      <div className="panel-body" style={{ padding: 0 }}>
        {events.length === 0 ? (
          <div className="empty-state">No audit events recorded.</div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Event type</th>
                  <th>Request ref</th>
                  <th>Actor</th>
                  <th>Metadata</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id}>
                    <td className="mono">{event.event_type}</td>
                    <td className="mono">{event.egress_request_id || '—'}</td>
                    <td className="mono">{event.actor_id || 'SYSTEM'}</td>
                    <td className="mono">{formatMetadata(event.metadata)}</td>
                    <td className="mono">{formatTime(event.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  )
}
