import { useCallback, useEffect, useState } from 'react'
import {
  ApiError,
  approveOnce,
  approveRememberOrg,
  denyRequest,
  getRequest,
  listRequests,
} from '../api/client.js'
import { Modal } from './Modal.jsx'
import { RequestDetail } from './RequestDetail.jsx'
import { StatusTag } from './StatusTag.jsx'

const DEFAULT_FILTERS = { status: 'pending', host: '', user: '', agent: '' }

function formatTime(value) {
  if (!value) {
    return ''
  }
  return new Date(value).toLocaleString()
}

export function InboxTab({ onStatus, onAuthRequired, refreshToken }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [appliedFilters, setAppliedFilters] = useState(DEFAULT_FILTERS)
  const [requests, setRequests] = useState([])
  const [selectedId, setSelectedId] = useState('')
  const [selectedRequest, setSelectedRequest] = useState(null)
  const [modal, setModal] = useState(null)
  const [denyReason, setDenyReason] = useState('policy_violation')
  const [denyNote, setDenyNote] = useState('')

  const loadQueue = useCallback(async () => {
    onStatus('Loading request queue…')
    try {
      const items = await listRequests(appliedFilters)
      setRequests(items)

      let nextId = selectedId
      if (!nextId && items.length) {
        nextId = items[0].id
      } else if (nextId && !items.some((item) => item.id === nextId)) {
        nextId = items[0]?.id || ''
      }
      setSelectedId(nextId)

      if (nextId) {
        const detail = await getRequest(nextId)
        setSelectedRequest(detail)
      } else {
        setSelectedRequest(null)
      }

      onStatus(`${items.length} record(s) loaded.`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load queue', 'error')
    }
  }, [appliedFilters, onAuthRequired, onStatus, selectedId])

  useEffect(() => {
    loadQueue()
  }, [loadQueue, refreshToken])

  useEffect(() => {
    const handle = window.setInterval(loadQueue, 15000)
    return () => window.clearInterval(handle)
  }, [loadQueue])

  async function selectRequest(id) {
    setSelectedId(id)
    try {
      const detail = await getRequest(id)
      setSelectedRequest(detail)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  async function runAction(action) {
    if (!selectedId) {
      return
    }
    try {
      await action()
      setModal(null)
      await loadQueue()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      await loadQueue()
      onStatus(err.message, 'error')
    }
  }

  const counts = {
    pending: requests.filter((item) => item.status === 'pending').length,
    approved: requests.filter((item) => item.status === 'approved').length,
    denied: requests.filter((item) => item.status === 'denied').length,
    autoApproved: requests.filter((item) => item.status === 'auto_approved').length,
  }

  return (
    <>
      <div className="stat-row">
        <div className="stat-box">
          <div className="stat-label">Pending</div>
          <div className="stat-value">{counts.pending}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Approved once</div>
          <div className="stat-value">{counts.approved}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Denied</div>
          <div className="stat-value">{counts.denied}</div>
        </div>
        <div className="stat-box">
          <div className="stat-label">Auto-approved</div>
          <div className="stat-value">{counts.autoApproved}</div>
        </div>
      </div>

      <div className="filter-row panel" style={{ padding: '0.5rem 0.65rem' }}>
        <label className="field-label" htmlFor="filter-status">
          Status
        </label>
        <select
          id="filter-status"
          value={filters.status}
          onChange={(event) => setFilters((prev) => ({ ...prev, status: event.target.value }))}
        >
          <option value="pending">Pending</option>
          <option value="">All</option>
          <option value="approved">Approved once</option>
          <option value="auto_approved">Auto-approved</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
        </select>
        <label className="field-label" htmlFor="filter-host">
          Host
        </label>
        <input
          id="filter-host"
          type="text"
          value={filters.host}
          placeholder="hostname"
          onChange={(event) => setFilters((prev) => ({ ...prev, host: event.target.value.trim() }))}
        />
        <label className="field-label" htmlFor="filter-user">
          User
        </label>
        <input
          id="filter-user"
          type="text"
          value={filters.user}
          onChange={(event) => setFilters((prev) => ({ ...prev, user: event.target.value.trim() }))}
        />
        <label className="field-label" htmlFor="filter-agent">
          Agent
        </label>
        <input
          id="filter-agent"
          type="text"
          value={filters.agent}
          onChange={(event) => setFilters((prev) => ({ ...prev, agent: event.target.value.trim() }))}
        />
        <button type="button" onClick={() => setAppliedFilters({ ...filters })}>
          Apply filters
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => {
            setFilters(DEFAULT_FILTERS)
            setAppliedFilters(DEFAULT_FILTERS)
          }}
        >
          Reset filters
        </button>
      </div>

      <div className="split-layout">
        <section className="panel">
          <div className="panel-head">Egress request queue</div>
          <div className="panel-body" style={{ padding: 0 }}>
            {requests.length === 0 ? (
              <div className="empty-state">
                {appliedFilters.status === 'pending'
                  ? 'No pending requests match current filters.'
                  : 'No records match current filters.'}
              </div>
            ) : (
              <div className="data-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Method</th>
                      <th>Destination</th>
                      <th>User</th>
                      <th>Agent</th>
                      <th>Requested</th>
                    </tr>
                  </thead>
                  <tbody>
                    {requests.map((item) => (
                      <tr
                        key={item.id}
                        className={`clickable ${item.id === selectedId ? 'selected' : ''}`}
                        onClick={() => selectRequest(item.id)}
                      >
                        <td>
                          <StatusTag status={item.status} />
                        </td>
                        <td className="mono">
                          {item.method}
                          {item.method === 'CONNECT' ? <div className="muted">TUNNEL</div> : null}
                        </td>
                        <td>
                          <div className="mono">
                            {item.host}:{item.port}
                          </div>
                          <div className="mono muted">{item.path}</div>
                        </td>
                        <td className="mono">{item.user_id}</td>
                        <td className="mono">{item.agent_id}</td>
                        <td className="mono">{formatTime(item.requested_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">Request record</div>
          <div className="panel-body">
            <RequestDetail
              request={selectedRequest}
              onApproveOnce={() => setModal('approve')}
              onApproveOrg={() => setModal('remember')}
              onDeny={() => {
                setDenyReason('policy_violation')
                setDenyNote('')
                setModal('deny')
              }}
            />
          </div>
        </section>
      </div>

      <Modal
        title="Confirm approval"
        open={modal === 'approve'}
        onClose={() => setModal(null)}
        actions={
          <>
            <button type="button" className="ghost" onClick={() => setModal(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="primary"
              onClick={() =>
                runAction(async () => {
                  await approveOnce(selectedId)
                  onStatus('Approve-once recorded.', 'ok')
                })
              }
            >
              Confirm
            </button>
          </>
        }
      >
        {selectedRequest ? (
          <>
            <p>
              Authorize one retry for{' '}
              <span className="mono">
                {selectedRequest.method} {selectedRequest.host}:{selectedRequest.port}
                {selectedRequest.path}
              </span>{' '}
              (agent <span className="mono">{selectedRequest.agent_id}</span>)?
            </p>
            {selectedRequest.method === 'CONNECT' ? (
              <div className="notice warn">CONNECT approval allows an HTTPS tunnel to this host.</div>
            ) : null}
          </>
        ) : null}
      </Modal>

      <Modal
        title="Approve and create org rule"
        open={modal === 'remember'}
        onClose={() => setModal(null)}
        actions={
          <>
            <button type="button" className="ghost" onClick={() => setModal(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="primary"
              onClick={() =>
                runAction(async () => {
                  await approveRememberOrg(selectedId)
                  onStatus('Org allow rule created.', 'ok')
                })
              }
            >
              Confirm
            </button>
          </>
        }
      >
        {selectedRequest ? (
          <>
            <p>
              Create org-scoped allow rule for{' '}
              <span className="mono">
                {selectedRequest.method} {selectedRequest.host}:{selectedRequest.port}
                {selectedRequest.path}
              </span>{' '}
              and approve this request?
            </p>
            <div className="notice warn">
              Future matching requests from any agent in this org will auto-approve and remain audited.
            </div>
          </>
        ) : null}
      </Modal>

      <Modal
        title="Deny request"
        open={modal === 'deny'}
        onClose={() => setModal(null)}
        actions={
          <>
            <button type="button" className="ghost" onClick={() => setModal(null)}>
              Cancel
            </button>
            <button
              type="button"
              className="danger"
              onClick={() =>
                runAction(async () => {
                  const feedback = denyNote.trim() ? `${denyReason}: ${denyNote.trim()}` : denyReason
                  await denyRequest(selectedId, feedback)
                  onStatus('Deny recorded.', 'ok')
                })
              }
            >
              Deny
            </button>
          </>
        }
      >
        <p className="notice">Deny creates a standing block for this agent and destination pattern.</p>
        <div className="filter-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <label className="field-label" htmlFor="deny-reason">
            Reason code
          </label>
          <select id="deny-reason" value={denyReason} onChange={(event) => setDenyReason(event.target.value)}>
            <option value="policy_violation">Policy violation</option>
            <option value="unknown_destination">Unknown destination</option>
            <option value="needs_investigation">Needs investigation</option>
            <option value="other">Other</option>
          </select>
          <label className="field-label" htmlFor="deny-note">
            Reviewer note
          </label>
          <textarea
            id="deny-note"
            value={denyNote}
            onChange={(event) => setDenyNote(event.target.value)}
            placeholder="Optional note"
          />
        </div>
      </Modal>
    </>
  )
}
