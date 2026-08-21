import { useEffect, useState } from 'react'
import { getAuth, saveAuth } from '../api/client.js'
import { Modal } from './Modal.jsx'

export function AuthModal({ open, onClose, onSaved, authConfig, authenticated }) {
  const [token, setToken] = useState('')
  const [approver, setApprover] = useState('')

  useEffect(() => {
    if (open) {
      const auth = getAuth()
      setToken(auth.token)
      setApprover(auth.approver)
    }
  }, [open])

  function handleSave() {
    saveAuth({ token, approver })
    onSaved()
    onClose()
  }

  const oidc = authConfig?.mode === 'oidc'

  // In OIDC mode with an identity-aware proxy in front, the browser already
  // carries a verified token on every request and the console has nothing to
  // collect. Showing a credential field here would invite someone to paste a
  // long-lived secret into a form that does not need one.
  if (oidc && authenticated) {
    return (
      <Modal
        title="Signed in"
        open={open}
        onClose={onClose}
        actions={
          <button type="button" className="primary" onClick={onClose}>
            Close
          </button>
        }
      >
        <p className="notice">
          You are authenticated through your organization&rsquo;s identity provider.
          Clearance does not store a password or session for you.
        </p>
        <dl className="kv">
          <dt>Mode</dt>
          <dd className="mono">oidc</dd>
          <dt>Issuer</dt>
          <dd className="mono">{authConfig.issuer || '—'}</dd>
        </dl>
        <p className="notice">
          Your role and organization come from Clearance&rsquo;s own directory, not
          from the identity provider. Ask an administrator to change your role.
        </p>
      </Modal>
    )
  }

  if (oidc) {
    return (
      <Modal
        title="Sign in required"
        open={open}
        onClose={onClose}
        actions={
          <>
            <button type="button" className="ghost" onClick={onClose}>
              Cancel
            </button>
            <button type="button" className="primary" onClick={handleSave}>
              Use this token
            </button>
          </>
        }
      >
        <p className="notice">
          This deployment authenticates through an identity provider
          {authConfig.issuer ? ` (${authConfig.issuer})` : ''}. Normally you reach the
          console through a sign-in flow and nothing needs to be entered here.
        </p>
        <p className="notice">
          If you are calling the API directly, paste an access token issued for
          this application. It is kept in this browser tab only and never sent
          anywhere except this control plane.
        </p>
        <div className="filter-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <label className="field-label" htmlFor="auth-token">
            Access token (OIDC)
          </label>
          <input
            id="auth-token"
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            autoComplete="off"
          />
        </div>
        {/* No approver field in OIDC mode: identity is taken from the verified
            token, so letting the browser assert an actor id would undo it. */}
      </Modal>
    )
  }

  return (
    <Modal
      title="Administrator Authentication"
      open={open}
      onClose={onClose}
      actions={
        <>
          <button type="button" className="ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="primary" onClick={handleSave}>
            Apply credentials
          </button>
        </>
      }
    >
      <p className="notice warn">
        This deployment is in <span className="mono">dev-token</span> mode. A shared
        static token cannot attribute actions to a person, so every audit entry
        records the same administrator. Not suitable for production.
      </p>
      <p className="notice">
        Gateway control-plane access requires an admin token when configured. Credentials are stored in this browser tab only.
      </p>
      <div className="filter-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
        <label className="field-label" htmlFor="auth-token">
          Admin token
        </label>
        <input
          id="auth-token"
          type="password"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          autoComplete="off"
        />
        <label className="field-label" htmlFor="auth-approver">
          Approver identifier
        </label>
        <input
          id="auth-approver"
          type="text"
          value={approver}
          onChange={(event) => setApprover(event.target.value)}
          placeholder="User ID or email"
        />
      </div>
    </Modal>
  )
}
