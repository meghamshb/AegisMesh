import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  listAgents,
  listUsers,
  registerAgent,
  revokeAgent,
  rotateAgentCredential,
} from '../api/client.js'
import { Modal } from './Modal.jsx'
import { StatusTag } from './StatusTag.jsx'

function formatTime(value) {
  if (!value) {
    return '—'
  }
  return new Date(value).toLocaleString()
}

const DEFAULT_FORM = { ownerUserId: '', name: '' }

export function AgentsTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [agents, setAgents] = useState([])
  const [users, setUsers] = useState([])
  const [registerOpen, setRegisterOpen] = useState(false)
  const [form, setForm] = useState(DEFAULT_FORM)
  const [credential, setCredential] = useState(null) // { agentName, token, tokenPrefix }
  const [copied, setCopied] = useState(false)

  const loadAgents = useCallback(async () => {
    onStatus('Loading agents…')
    try {
      const items = await listAgents()
      setAgents(items)
      onStatus(`${items.length} agent(s) loaded.`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load agents', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadAgents()
      listUsers({ status: 'active' })
        .then(setUsers)
        .catch(() => {})
    }
  }, [active, loadAgents, refreshToken])

  // Agents last_seen changes independently of admin actions, so poll it on
  // its own slower cadence (5.7.10) rather than only on navigation/mutation.
  useEffect(() => {
    if (!active) return undefined
    const handle = window.setInterval(loadAgents, 20000)
    return () => window.clearInterval(handle)
  }, [active, loadAgents])

  function openRegister() {
    setForm({ ownerUserId: users[0]?.id || '', name: '' })
    setRegisterOpen(true)
  }

  async function handleRegister() {
    if (!form.ownerUserId || !form.name.trim()) {
      onStatus('Owner and name are required.', 'error')
      return
    }
    try {
      const result = await registerAgent({ ownerUserId: form.ownerUserId, name: form.name.trim() })
      setRegisterOpen(false)
      setCopied(false)
      setCredential({
        agentName: result.agent.name,
        token: result.credential.token,
        tokenPrefix: result.credential.token_prefix,
      })
      await loadAgents()
      onStatus('Agent registered.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  async function handleRotate(agent) {
    const confirmed = window.confirm(
      `Rotate the credential for ${agent.name}? Its current token will stop working immediately.`,
    )
    if (!confirmed) {
      return
    }
    try {
      const result = await rotateAgentCredential(agent.id)
      setCopied(false)
      setCredential({
        agentName: agent.name,
        token: result.credential.token,
        tokenPrefix: result.credential.token_prefix,
      })
      onStatus('Credential rotated.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  async function handleRevoke(agent) {
    const confirmed = window.confirm(`Revoke ${agent.name}? It will no longer be able to authenticate.`)
    if (!confirmed) {
      return
    }
    try {
      await revokeAgent(agent.id)
      await loadAgents()
      onStatus('Agent revoked.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  function copyToken() {
    if (!navigator.clipboard) {
      return
    }
    navigator.clipboard
      .writeText(credential.token)
      .then(() => setCopied(true))
      .catch(() => {
        // Clipboard permission can be denied by the browser; the credential
        // text is still selectable (user-select: all) as a manual fallback.
      })
  }

  return (
    <section className="panel">
      <div className="panel-head" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Agents</span>
        <button type="button" className="primary" onClick={openRegister} disabled={users.length === 0}>
          Register agent
        </button>
      </div>
      <div className="panel-body" style={{ padding: 0 }}>
        {agents.length === 0 ? (
          <div className="empty-state">No agents registered.</div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Owner</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr key={agent.id}>
                    <td title={agent.id}>{agent.name}</td>
                    <td title={agent.owner_user_id}>{agent.owner_display_name || <span className="mono muted">{agent.owner_user_id}</span>}</td>
                    <td>
                      <StatusTag status={agent.status} />
                    </td>
                    <td className="mono muted">{formatTime(agent.last_seen_at)}</td>
                    <td className="mono">{formatTime(agent.created_at)}</td>
                    <td style={{ display: 'flex', gap: '0.4rem' }}>
                      <button
                        type="button"
                        disabled={agent.status !== 'active'}
                        onClick={() => handleRotate(agent)}
                      >
                        Rotate
                      </button>
                      <button
                        type="button"
                        className="danger"
                        disabled={agent.status !== 'active'}
                        onClick={() => handleRevoke(agent)}
                      >
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
        title="Register agent"
        open={registerOpen}
        onClose={() => setRegisterOpen(false)}
        actions={
          <>
            <button type="button" className="ghost" onClick={() => setRegisterOpen(false)}>
              Cancel
            </button>
            <button type="button" className="primary" onClick={handleRegister}>
              Register
            </button>
          </>
        }
      >
        <div className="filter-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <label className="field-label" htmlFor="agent-owner">Owner</label>
          <select
            id="agent-owner"
            value={form.ownerUserId}
            onChange={(event) => setForm((prev) => ({ ...prev, ownerUserId: event.target.value }))}
          >
            {users.map((user) => (
              <option key={user.id} value={user.id}>
                {user.display_name}
              </option>
            ))}
          </select>
          <label className="field-label" htmlFor="agent-name">Agent name</label>
          <input
            id="agent-name"
            type="text"
            value={form.name}
            placeholder="alice-macbook-hermes"
            onChange={(event) => setForm((prev) => ({ ...prev, name: event.target.value }))}
          />
        </div>
      </Modal>

      <Modal
        title="Agent credential"
        open={Boolean(credential)}
        onClose={() => setCredential(null)}
        actions={
          <button type="button" className="primary" onClick={() => setCredential(null)}>
            Done
          </button>
        }
      >
        {credential ? (
          <>
            <p>
              Credential for <strong>{credential.agentName}</strong>:
            </p>
            <div className="credential-box mono">{credential.token}</div>
            <div className="filter-row" style={{ marginTop: '0.5rem' }}>
              <button type="button" onClick={copyToken}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="notice warn" style={{ marginTop: '0.5rem' }}>
              This credential is shown once. Copy it now — it cannot be retrieved again after closing this dialog.
            </div>
          </>
        ) : null}
      </Modal>
    </section>
  )
}
