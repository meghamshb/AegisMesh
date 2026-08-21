import { useCallback, useEffect, useState } from 'react'
import { ApiError, createUser, listUsers, setUserStatus } from '../api/client.js'
import { Modal } from './Modal.jsx'
import { StatusTag } from './StatusTag.jsx'

function formatTime(value) {
  if (!value) {
    return ''
  }
  return new Date(value).toLocaleString()
}

const DEFAULT_FORM = { displayName: '', email: '', role: 'member' }

export function UsersTab({ onStatus, onAuthRequired, refreshToken, active }) {
  const [users, setUsers] = useState([])
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState(DEFAULT_FORM)

  const loadUsers = useCallback(async () => {
    onStatus('Loading users…')
    try {
      const items = await listUsers()
      setUsers(items)
      onStatus(`${items.length} user(s) loaded.`, 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message || 'Failed to load users', 'error')
    }
  }, [onAuthRequired, onStatus])

  useEffect(() => {
    if (active) {
      loadUsers()
    }
  }, [active, loadUsers, refreshToken])

  function openCreate() {
    setForm(DEFAULT_FORM)
    setCreateOpen(true)
  }

  async function handleCreate() {
    if (!form.displayName.trim()) {
      onStatus('Display name is required.', 'error')
      return
    }
    try {
      await createUser(form)
      setCreateOpen(false)
      await loadUsers()
      onStatus('User created.', 'ok')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onAuthRequired()
      }
      onStatus(err.message, 'error')
    }
  }

  async function toggleStatus(user) {
    const nextStatus = user.status === 'active' ? 'disabled' : 'active'
    const confirmed = window.confirm(
      nextStatus === 'disabled'
        ? `Disable ${user.display_name}? All of their agents will immediately stop authenticating.`
        : `Re-enable ${user.display_name}? Their agents will authenticate again immediately.`,
    )
    if (!confirmed) {
      return
    }
    try {
      await setUserStatus(user.id, nextStatus)
      await loadUsers()
      onStatus(`${user.display_name} ${nextStatus === 'disabled' ? 'disabled' : 're-enabled'}.`, 'ok')
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
        <span>Users</span>
        <button type="button" className="primary" onClick={openCreate}>
          Create user
        </button>
      </div>
      <div className="panel-body" style={{ padding: 0 }}>
        {users.length === 0 ? (
          <div className="empty-state">No users on file.</div>
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td title={user.id}>{user.display_name}</td>
                    <td className="mono muted">{user.email || '—'}</td>
                    <td className="mono">{user.role}</td>
                    <td>
                      <StatusTag status={user.status} />
                    </td>
                    <td className="mono">{formatTime(user.created_at)}</td>
                    <td>
                      <button
                        type="button"
                        className={user.status === 'active' ? 'danger' : 'primary'}
                        onClick={() => toggleStatus(user)}
                      >
                        {user.status === 'active' ? 'Disable' : 'Enable'}
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
        title="Create user"
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
          <label className="field-label" htmlFor="user-name">Display name</label>
          <input
            id="user-name"
            type="text"
            value={form.displayName}
            onChange={(event) => setForm((prev) => ({ ...prev, displayName: event.target.value }))}
            placeholder="Alice"
          />
          <label className="field-label" htmlFor="user-email">Email</label>
          <input
            id="user-email"
            type="email"
            value={form.email}
            onChange={(event) => setForm((prev) => ({ ...prev, email: event.target.value }))}
            placeholder="alice@example.com"
          />
          <label className="field-label" htmlFor="user-role">Role</label>
          <select
            id="user-role"
            value={form.role}
            onChange={(event) => setForm((prev) => ({ ...prev, role: event.target.value }))}
          >
            <option value="member">Member</option>
            <option value="approver">Approver</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </Modal>
    </section>
  )
}
