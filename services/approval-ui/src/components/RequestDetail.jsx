import { StatusTag } from './StatusTag.jsx'

function DetailField({ label, value, mono = false }) {
  return (
    <div className="detail-field">
      <span className="field-label">{label}</span>
      <div className={mono ? 'mono' : ''}>{value}</div>
    </div>
  )
}

function formatTime(value) {
  if (!value) {
    return '—'
  }
  return new Date(value).toLocaleString()
}

export function RequestDetail({
  request,
  onApproveOnce,
  onApproveOrg,
  onDeny,
}) {
  if (!request) {
    return <div className="empty-state">Select a request from the queue.</div>
  }

  const isPending = request.status === 'pending'
  const isConnect = request.method === 'CONNECT'
  const rememberDisabled = !isPending || isConnect

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <StatusTag status={request.status} />
        <span className="mono muted">{request.id}</span>
      </div>

      {isConnect ? (
        <div className="notice warn">
          <strong>CONNECT tunnel.</strong> Approval grants HTTPS tunnel access to the destination host for this agent. Org-wide remember is not permitted for CONNECT.
        </div>
      ) : null}

      <div className="detail-grid">
        <DetailField label="Destination" value={`${request.host}:${request.port}`} mono />
        <DetailField label="Method" value={request.method} mono />
        <DetailField label="Path" value={request.path || '/'} mono />
        <DetailField label="Scheme" value={request.scheme} mono />
        <DetailField label="User" value={request.user_id} mono />
        <DetailField label="Agent" value={request.agent_id} mono />
        <DetailField label="Organization" value={request.org_id} mono />
        <DetailField label="Requested" value={formatTime(request.requested_at)} mono />
        <DetailField label="Decided by" value={request.decided_by || '—'} mono />
        <DetailField label="Decided at" value={formatTime(request.decided_at)} mono />
        <DetailField label="Rule ref" value={request.rule_id || '—'} mono />
        <DetailField label="Notes" value={request.error_message || '—'} />
      </div>

      <div className="detail-actions">
        <button type="button" className="primary" disabled={!isPending} onClick={onApproveOnce}>
          Approve once
        </button>
        <button
          type="button"
          disabled={rememberDisabled}
          title={isConnect ? 'CONNECT tunnels cannot be remembered for org' : undefined}
          onClick={onApproveOrg}
        >
          Approve + org rule
        </button>
        <button type="button" className="danger" disabled={!isPending} onClick={onDeny}>
          Deny
        </button>
      </div>

      {isPending ? (
        <p className="notice muted">
          Approve once grants a single retry. Approve + org rule creates a persistent allow pattern for matching future traffic.
        </p>
      ) : (
        <p className="notice muted">This request is closed. Refresh the queue if another reviewer may have acted.</p>
      )}
    </>
  )
}
