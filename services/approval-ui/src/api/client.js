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
    headers.Authorization = `Bearer ${token}`
    headers['X-Admin-Token'] = token
  }
  if (approver) {
    headers['X-Gateway-Approver'] = approver
  }
  return headers
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
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
    throw new ApiError(body.error || 'Admin token required', 401)
  }
  if (response.status === 409) {
    throw new ApiError(body.error || 'Request already decided by another reviewer', 409)
  }
  if (!response.ok) {
    throw new ApiError(body.error || `Request failed (${response.status})`, response.status)
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
  return apiFetch(`/api/v1/requests/${id}/approve`, {
    method: 'POST',
    body: JSON.stringify({ remember: true, scope: 'org' }),
  })
}

export async function denyRequest(id, feedback) {
  return apiFetch(`/api/v1/requests/${id}/deny`, {
    method: 'POST',
    body: JSON.stringify({ feedback }),
  })
}

export async function revokeRule(id) {
  return apiFetch(`/api/v1/rules/${id}`, { method: 'DELETE' })
}
