import { useCallback, useEffect, useState } from 'react'
import { ApiError, listRules, revokeRule } from '../api/client.js'
import { StatusTag } from './StatusTag.jsx'

function formatTime(value) {
  if (!value) {
    return ''
  }
  return new Date(value).toLocaleString()
}

export function RulesTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [rules, setRules] = useState([])

  const loadRules = useCallback(async () => {
    onStatus('Loading policy rules…')
    try {
      const items = await listRules()
      setRules(items)
      onStatus(`${items.length} rule(s) loaded.`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load rules', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadRules()
    }
  }, [active, loadRules, refreshToken])

  async function handleRevoke(ruleId) {
    const confirmed = window.confirm(
      `Revoke rule ${ruleId}? Matching traffic will require approval again.`,
    )
    if (!confirmed) {
      return
    }
    try {
      await revokeRule(ruleId)
      await loadRules()
      onStatus('Rule revoked.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  return (
    <section className="panel">
      <div className="panel-head">Policy rules registry</div>
      <div className="panel-body" style={{ padding: 0 }}>
        {rules.length === 0 ? (
          <div className="empty-state">No policy rules on file.</div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Effect</th>
                  <th>Scope</th>
                  <th>Destination</th>
                  <th>Method</th>
                  <th>Path prefix</th>
                  <th>Created by</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <StatusTag status={rule.effect} />
                    </td>
                    <td className="mono">{rule.scope}</td>
                    <td className="mono">
                      {rule.host}:{rule.port}
                    </td>
                    <td className="mono">{rule.method}</td>
                    <td className="mono">{rule.path_prefix}</td>
                    <td className="mono">{rule.created_by}</td>
                    <td className="mono">{formatTime(rule.created_at)}</td>
                    <td>
                      <button type="button" className="danger" onClick={() => handleRevoke(rule.id)}>
                        Revoke
                      </button>
                    </td>
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
