const TOKEN_KEY = 'gatewayAdminToken'
const APPROVER_KEY = 'gatewayApproverId'

export function getAuth() {
  return {
    token: sessionStorage.getItem(TOKEN_KEY) || '',
    approver: sessionStorage.getItem(APPROVER_KEY) || '',
  }
}

export function saveAuth({ token, approver }) {
  sessionStorage.setItem(TOKEN_KEY, token.trim())
  sessionStorage.setItem(APPROVER_KEY, approver.trim())
}

export function authHeaders({ token, approver }, includeJson = false) {
  const headers = {}
  if (includeJson) {
    headers['Content-Type'] = 'application/json'
  }
  if (token) {
    // Sent as both because the two modes read different headers. In OIDC mode
    // the server ignores X-Admin-Token entirely, so this stays correct either
    // way without the client having to know the mode before its first call.
    headers.Authorization = `Bearer ${token}`
    headers['X-Admin-Token'] = token
  }
  if (approver) {
    headers['X-Gateway-Approver'] = approver
  }
  return headers
}

// Cached because every tab render would otherwise re-request it; the mode
// cannot change without a server restart.
let cachedAuthConfig = null

// fetchAuthConfig asks the server how to authenticate. It is deliberately
// unauthenticated, so it works before the console holds any credential.
export async function fetchAuthConfig() {
  if (cachedAuthConfig) {
    return cachedAuthConfig
  }
  try {
    const res = await fetch('/api/v1/auth/config')
    if (!res.ok) {
      throw new Error(`status ${res.status}`)
    }
    cachedAuthConfig = await res.json()
  } catch {
    // An older server has no such endpoint. Assume the pre-5.13 behaviour
    // rather than locking the operator out of a console that would work.
    cachedAuthConfig = { mode: 'dev-token', dev_token_required: true }
  }
  return cachedAuthConfig
}

// probeAuthenticated reports whether the browser can already reach the control
// plane without the console supplying anything.
//
// This is what makes the token modal unnecessary in OIDC mode: a deployment
// behind an identity-aware proxy (oauth2-proxy, Entra Application Proxy,
// Cloudflare Access) already carries a verified Authorization header on every
// request, so the console has nothing to ask for.
export async function probeAuthenticated() {
  try {
    const res = await fetch('/api/v1/organizations/current', {
      headers: authHeaders(getAuth()),
    })
    return res.ok
  } catch {
    return false
  }
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

// Server errors come back as {"error":{"code","message"}}; a couple of
// hand-written client-side fallbacks below still pass a plain string. This
// normalizes either shape into a plain message string.
function errorMessage(body, fallback) {
  const err = body && body.error
  if (!err) return fallback
  if (typeof err === 'string') return err
  return err.message || fallback
}

export async function apiFetch(path, options = {}) {
  const auth = getAuth()
  const headers = authHeaders(auth, Boolean(options.body))
  Object.assign(headers, options.headers || {})

  const response = await fetch(path, { ...options, headers })

  if (response.status === 204) {
    return null
  }

  const body = await response.json().catch(() => ({}))

  if (response.status === 401) {
    throw new ApiError(errorMessage(body, 'Admin token required'), 401)
  }
  if (response.status === 409) {
    throw new ApiError(errorMessage(body, 'Request already decided by another reviewer'), 409)
  }
  if (!response.ok) {
    throw new ApiError(errorMessage(body, `Request failed (${response.status})`), response.status)
  }

  return body
}

export async function listRequests(filters) {
  const params = new URLSearchParams({ limit: '100' })
  if (filters.status) params.set('status', filters.status)
  if (filters.host) params.set('host', filters.host)
  if (filters.user) params.set('user_id', filters.user)
  if (filters.agent) params.set('agent_id', filters.agent)
  const body = await apiFetch(`/api/v1/requests?${params}`)
  return body.items || []
}

export async function getRequest(id) {
  return apiFetch(`/api/v1/requests/${id}`)
}

export async function listRules() {
  const body = await apiFetch('/api/v1/rules')
  return body.items || []
}

export async function listAudit() {
  const body = await apiFetch('/api/v1/audit')
  return body.items || []
}

export async function approveOnce(id) {
  return apiFetch(`/api/v1/requests/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export async function approveRememberOrg(id) {
  return approveRemember(id, 'org')
}

export async function approveRemember(id, scope) {
  return apiFetch(`/api/v1/requests/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({ remember: true, scope }),
  })
}

export async function denyRequest(id, feedback) {
  return apiFetch(`/api/v1/requests/${id}/deny`, {
    method: 'POST',
    body: JSON.stringify({ feedback }),
  })
}

export async function createRule(rule) {
  return apiFetch('/api/v1/rules', {
    method: 'POST',
    body: JSON.stringify(rule),
  })
}

export async function revokeRule(id) {
  return apiFetch(`/api/v1/rules/${id}`, { method: 'DELETE' })
}

export async function listUsers(filters = {}) {
  const params = new URLSearchParams({ limit: '200' })
  if (filters.status) params.set('status', filters.status)
  const body = await apiFetch(`/api/v1/users?${params}`)
  return body.items || []
}

export async function getUser(id) {
  return apiFetch(`/api/v1/users/${id}`)
}

export async function createUser({ displayName, email, role }) {
  return apiFetch('/api/v1/users', {
    method: 'POST',
    body: JSON.stringify({ display_name: displayName, email: email || undefined, role }),
  })
}

export async function setUserStatus(id, status) {
  return apiFetch(`/api/v1/users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  })
}

export async function listAgents(filters = {}) {
  const params = new URLSearchParams({ limit: '200' })
  if (filters.userId) params.set('user_id', filters.userId)
  if (filters.status) params.set('status', filters.status)
  const body = await apiFetch(`/api/v1/agents?${params}`)
  return body.items || []
}

export async function getAgent(id) {
  return apiFetch(`/api/v1/agents/${id}`)
}

export async function registerAgent({ ownerUserId, name }) {
  return apiFetch('/api/v1/agents', {
    method: 'POST',
    body: JSON.stringify({ owner_user_id: ownerUserId, name }),
  })
}

export async function renameAgent(id, name) {
  return apiFetch(`/api/v1/agents/${id}`, {
    method: 'PATCH',
    body: JSON.stringify({ name }),
  })
}

export async function rotateAgentCredential(id) {
  return apiFetch(`/api/v1/agents/${id}/credentials/rotate`, { method: 'POST' })
}

export async function revokeAgent(id) {
  return apiFetch(`/api/v1/agents/${id}/revoke`, { method: 'POST' })
}

export async function listGateways() {
  const body = await apiFetch('/api/v1/gateways')
  return body.items || []
}
