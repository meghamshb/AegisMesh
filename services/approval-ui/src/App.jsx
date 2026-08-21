import { useCallback, useEffect, useState } from 'react'
import { AuthModal } from './components/AuthModal.jsx'
import { fetchAuthConfig, probeAuthenticated } from './api/client.js'
import { AgentsTab } from './components/AgentsTab.jsx'
import { AuditTab } from './components/AuditTab.jsx'
import { GatewaysTab } from './components/GatewaysTab.jsx'
import { InboxTab } from './components/InboxTab.jsx'
import { RulesTab } from './components/RulesTab.jsx'
import { UsersTab } from './components/UsersTab.jsx'

const TABS = [
  { id: 'requests', label: 'Inbox' },
  { id: 'rules', label: 'Rules' },
  { id: 'users', label: 'Users' },
  { id: 'agents', label: 'Agents' },
  { id: 'gateways', label: 'Gateways' },
  { id: 'audit', label: 'Audit' },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('requests')
  const [status, setStatus] = useState({ message: 'Initializing…', kind: '' })
  const [authOpen, setAuthOpen] = useState(false)
  const [refreshToken, setRefreshToken] = useState(0)
  const [authConfig, setAuthConfig] = useState(null)
  const [authenticated, setAuthenticated] = useState(false)

  // Discover how this deployment authenticates before rendering anything that
  // asks for a credential. In OIDC mode behind an identity-aware proxy the
  // console is already authenticated and never needs to prompt.
  useEffect(() => {
    let cancelled = false
    async function load() {
      const config = await fetchAuthConfig()
      const ok = await probeAuthenticated()
      if (!cancelled) {
        setAuthConfig(config)
        setAuthenticated(ok)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [refreshToken])

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
        <h1>Clearance — Egress Control</h1>
        <span className="sys-meta">Outbound approval console · single-host deployment</span>
      </header>

      <div className="toolbar">
        <button type="button" className="primary" onClick={handleRefresh}>
          Refresh data
        </button>
        <button type="button" className="auth-trigger" onClick={() => setAuthOpen(true)}>
          {authConfig?.mode === 'oidc'
            ? (authenticated ? 'Signed in' : 'Sign in')
            : 'Session / credentials'}
        </button>
        {authConfig?.mode === 'dev-token' ? (
          <span className="dev-mode-badge" title="A shared static token cannot attribute actions to a person">
            DEV-TOKEN MODE
          </span>
        ) : null}
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
        {activeTab === 'users' ? (
          <UsersTab
            active
            onStatus={onStatus}
            onAuthRequired={onAuthRequired}
            refreshToken={refreshToken}
          />
        ) : null}
        {activeTab === 'agents' ? (
          <AgentsTab
            active
            onStatus={onStatus}
            onAuthRequired={onAuthRequired}
            refreshToken={refreshToken}
          />
        ) : null}
        {activeTab === 'gateways' ? (
          <GatewaysTab
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

      <AuthModal
        open={authOpen}
        onClose={() => setAuthOpen(false)}
        onSaved={handleAuthSaved}
        authConfig={authConfig}
        authenticated={authenticated}
      />
    </div>
  )
}
