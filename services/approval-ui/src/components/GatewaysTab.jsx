import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, listGateways } from '../api/client.js'
import { StatusTag } from './StatusTag.jsx'

// Liveness thresholds, in seconds since the last heartbeat.
//
// These are display semantics only, NOT a security control: a gateway shown as
// "offline" has not checked in recently, which is not the same as being
// revoked or unable to enforce policy. A gateway that loses the control plane
// keeps enforcing its last-known-good snapshot (Phase 5.9) and will read as
// stale here while still blocking traffic correctly. Revocation is the only
// state that actually stops a gateway.
const ONLINE_WITHIN_SECONDS = 30
const STALE_WITHIN_SECONDS = 120

// Poll often enough that the fleet view tracks the demo's heartbeat interval.
const POLL_INTERVAL_MS = 5000

function secondsSince(value) {
  if (!value) return null
  const then = new Date(value).getTime()
  if (Number.isNaN(then)) return null
  return Math.max(0, Math.round((Date.now() - then) / 1000))
}

export function liveness(gateway, nowSeconds = secondsSince(gateway.last_seen_at)) {
  if (gateway.status === 'revoked') return 'revoked'
  if (nowSeconds === null) return 'offline'
  if (nowSeconds < ONLINE_WITHIN_SECONDS) return 'online'
  if (nowSeconds < STALE_WITHIN_SECONDS) return 'stale'
  return 'offline'
}

function formatAge(seconds) {
  if (seconds === null) return 'never'
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  return `${Math.floor(seconds / 3600)}h ago`
}

export function GatewaysTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [gateways, setGateways] = useState([])
  // Re-render on a timer so "last seen" ages even when no fetch has returned.
  const [, setTick] = useState(0)
  const quietRef = useRef(false)

  const loadGateways = useCallback(async () => {
    if (!quietRef.current) {
      onStatus('Loading gateways…')
    }
    try {
      const items = await listGateways()
      setGateways(items)
      if (!quietRef.current) {
        onStatus(`${items.length} gateway(s) loaded.`, 'ok')
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load gateways', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (!active) return undefined
    quietRef.current = false
    loadGateways()

    // Background refreshes stay quiet so they do not stomp on whatever the
    // status line is currently showing the operator.
    const poll = setInterval(() => {
      quietRef.current = true
      loadGateways()
    }, POLL_INTERVAL_MS)
    const age = setInterval(() => setTick((n) => n + 1), 1000)

    return () => {
      clearInterval(poll)
      clearInterval(age)
    }
  }, [active, loadGateways, refreshToken])

  return (
    <section className="panel">
      <div className="panel-head">Gateways</div>
      <div className="panel-body" style={{ padding: 0 }}>
        {gateways.length === 0 ? (
          <div className="empty-state">
            No gateways registered. A distributed gateway registers itself with
            <span className="mono"> POST /api/v1/gateways</span>.
          </div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Gateway</th>
                  <th>Status</th>
                  <th>Version</th>
                  <th>Last seen</th>
                  <th>Policy version</th>
                  <th>Agents recently seen</th>
                </tr>
              </thead>
              <tbody>
                {gateways.map((gateway) => {
                  const age = secondsSince(gateway.last_seen_at)
                  return (
                    <tr key={gateway.id}>
                      <td title={gateway.id}>{gateway.name}</td>
                      <td>
                        <StatusTag status={liveness(gateway, age)} />
                      </td>
                      <td className="mono">{gateway.version || '—'}</td>
                      <td className="mono">{formatAge(age)}</td>
                      <td className="mono">{gateway.policy_version ?? 0}</td>
                      <td className="mono">{gateway.active_agents ?? 0}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="panel-foot muted">
        Liveness is a display hint, not an enforcement signal — a gateway that
        cannot reach the control plane keeps enforcing its last known policy.
      </div>
    </section>
  )
}
