import { useCallback, useEffect, useState } from 'react'
import { ApiError, createRule, listRules, revokeRule } from '../api/client.js'
import { Modal } from './Modal.jsx'
import { StatusTag } from './StatusTag.jsx'

function formatTime(value) {
  if (!value) {
    return ''
  }
  return new Date(value).toLocaleString()
}

const DEFAULT_RULE_FORM = {
  scope: 'org',
  scopeRefId: '',
  effect: 'allow',
  host: '',
  port: 443,
  method: '*',
  pathPrefix: '/',
}

export function RulesTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [rules, setRules] = useState([])
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState(DEFAULT_RULE_FORM)

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

  function openCreate() {
    setForm(DEFAULT_RULE_FORM)
    setCreateOpen(true)
  }

  async function handleCreate() {
    try {
      await createRule({
        scope: form.scope,
        scope_ref_id: form.scope === 'org' ? undefined : form.scopeRefId.trim(),
        effect: form.effect,
        host: form.host.trim(),
        port: Number(form.port) || 443,
        method: form.method.trim() || '*',
        path_prefix: form.pathPrefix.trim() || '/',
      })
      setCreateOpen(false)
      await loadRules()
      onStatus('Rule created.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  return (
    <section className="panel">
      <div className="panel-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Policy rules registry</span>
        <button type="button" className="primary" onClick={openCreate}>
          Create rule
        </button>
      </div>
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
                  <th>Applies to</th>
                  <th>Destination</th>
                  <th>Method</th>
                  <th>Path prefix</th>
                  <th>Expires</th>
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
                    <td title={rule.scope_ref_id}>{rule.scope_display_name || <span className="mono muted">{rule.scope_ref_id}</span>}</td>
                    <td className="mono">
                      {rule.host}:{rule.port}
                    </td>
                    <td className="mono">{rule.method}</td>
                    <td className="mono">{rule.path_prefix}</td>
                    <td className="mono muted">{rule.expires_at ? formatTime(rule.expires_at) : 'never'}</td>
                    <td title={rule.created_by}>{rule.created_by_display_name || <span className="mono muted">{rule.created_by}</span>}</td>
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

      <Modal
        title="Create policy rule"
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        actions={
          <>
            <button type="button" className="ghost" onClick={() => setCreateOpen(false)}>
              Cancel
            </button>
            <button type="button" className="primary" onClick={handleCreate}>
              Create
            </button>
          </>
        }
      >
        <div className="filter-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <label className="field-label" htmlFor="rule-scope">Scope</label>
          <select
            id="rule-scope"
            value={form.scope}
            onChange={(event) => setForm((prev) => ({ ...prev, scope: event.target.value }))}
          >
            <option value="org">Organization</option>
            <option value="user">User</option>
            <option value="agent">Agent</option>
          </select>

          {form.scope !== 'org' ? (
            <>
              <label className="field-label" htmlFor="rule-scope-ref">
                {form.scope === 'user' ? 'User ID' : 'Agent ID'}
              </label>
              <input
                id="rule-scope-ref"
                type="text"
                value={form.scopeRefId}
                placeholder="uuid — copy from the Users or Agents tab"
                onChange={(event) => setForm((prev) => ({ ...prev, scopeRefId: event.target.value }))}
              />
            </>
          ) : null}

          <label className="field-label" htmlFor="rule-effect">Effect</label>
          <select
            id="rule-effect"
            value={form.effect}
            onChange={(event) => setForm((prev) => ({ ...prev, effect: event.target.value }))}
          >
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>

          <label className="field-label" htmlFor="rule-host">Host</label>
          <input
            id="rule-host"
            type="text"
            value={form.host}
            placeholder="api.github.com"
            onChange={(event) => setForm((prev) => ({ ...prev, host: event.target.value }))}
          />

          <label className="field-label" htmlFor="rule-port">Port</label>
          <input
            id="rule-port"
            type="number"
            value={form.port}
            onChange={(event) => setForm((prev) => ({ ...prev, port: event.target.value }))}
          />

          <label className="field-label" htmlFor="rule-method">Method</label>
          <input
            id="rule-method"
            type="text"
            value={form.method}
            placeholder="GET, POST, or *"
            onChange={(event) => setForm((prev) => ({ ...prev, method: event.target.value }))}
          />

          <label className="field-label" htmlFor="rule-path">Path prefix</label>
          <input
            id="rule-path"
            type="text"
            value={form.pathPrefix}
            placeholder="/"
            onChange={(event) => setForm((prev) => ({ ...prev, pathPrefix: event.target.value }))}
          />
        </div>
      </Modal>
    </section>
  )
}
