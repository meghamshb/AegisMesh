import { useCallback, useState } from 'react'
import { AuthModal } from './components/AuthModal.jsx'
import { AuditTab } from './components/AuditTab.jsx'
import { InboxTab } from './components/InboxTab.jsx'
import { RulesTab } from './components/RulesTab.jsx'

const TABS = [
  { id: 'requests', label: 'Inbox' },
  { id: 'rules', label: 'Rules' },
  { id: 'audit', label: 'Audit' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('requests')
  const [status, setStatus] = useState({ message: 'Initializing…', kind: '' })
  const [authOpen, setAuthOpen] = useState(false)
  const [refreshToken, setRefreshToken] = useState(0)

  const onStatus = useCallback((message, kind = '') => {
    setStatus({ message, kind })
  }, [])

  const onAuthRequired = useCallback(() => {
    setAuthOpen(true)
  }, [])

  function handleRefresh() {
    setRefreshToken((value) => value + 1)
  }

  function handleAuthSaved() {
    setRefreshToken((value) => value + 1)
  }

  return (
    <div className="app-shell">
      <header className="sys-header">
        <h1>Hermes Policy Gateway — Egress Control</h1>
        <span className="sys-meta">Outbound approval console · single-host deployment</span>
      </header>

      <div className="toolbar">
        <button type="button" className="primary" onClick={handleRefresh}>
          Refresh data
        </button>
        <button type="button" className="auth-trigger" onClick={() => setAuthOpen(true)}>
          Session / credentials
        </button>
        <span className="spacer" />
        <span className={`status-line ${status.kind}`}>{status.message}</span>
      </div>

      <nav className="tab-bar" aria-label="Primary views">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={activeTab === tab.id ? 'active' : ''}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="main-content">
        {activeTab === 'requests' ? (
          <InboxTab
            onStatus={onStatus}
            onAuthRequired={onAuthRequired}
            refreshToken={refreshToken}
          />
        ) : null}
        {activeTab === 'rules' ? (
          <RulesTab
            active
            onStatus={onStatus}
            onAuthRequired={onAuthRequired}
            refreshToken={refreshToken}
          />
        ) : null}
        {activeTab === 'audit' ? (
          <AuditTab
            active
            onStatus={onStatus}
            onAuthRequired={onAuthRequired}
            refreshToken={refreshToken}
          />
        ) : null}
      </main>

      <AuthModal open={authOpen} onClose={() => setAuthOpen(false)} onSaved={handleAuthSaved} />
    </div>
  )
}
