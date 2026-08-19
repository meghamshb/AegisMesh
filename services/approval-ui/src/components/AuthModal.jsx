import { useEffect, useState } from 'react'
import { getAuth, saveAuth } from '../api/client.js'
import { Modal } from './Modal.jsx'

export function AuthModal({ open, onClose, onSaved }) {
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
