export type Language = 'ru' | 'en'
export type Role = 'super_admin' | 'administrator' | 'viewer'

export interface User {
  id: string
  username: string
  role: Role
}

export interface Session {
  user: User
  csrf_token: string
  expires_at: string
}

export interface SetupStatus {
  configured: boolean
  token_configured: boolean
  language: Language
}

export interface Settings {
  organization: string
  instance_name: string
  agent_url: string | null
  heartbeat_seconds: number
  language: Language
  version: string
}

export interface AuditEvent {
  id: string
  action: string
  actor_id: string | null
  target_id: string | null
  details: Record<string, string>
  created_at: string
}

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code)
  }
}

export async function api<T>(path: string, options: { method?: string; body?: unknown; csrf?: string; signal?: AbortSignal; responseType?: 'blob' } = {}): Promise<T> {
  const { method = 'GET', body, csrf, signal, responseType } = options
  const headers = new Headers()
  if (method !== 'GET') headers.set('X-DeployCore-Request', '1')
  if (csrf) headers.set('X-CSRF-Token', csrf)
  const raw = body instanceof Blob
  if (body !== undefined) headers.set('Content-Type', raw ? 'application/octet-stream' : 'application/json')
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: raw ? body : body === undefined ? undefined : JSON.stringify(body),
    signal,
    cache: 'no-store',
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    throw new ApiError(response.status, typeof payload?.detail === 'string' ? payload.detail : '')
  }
  const deadline = response.headers.get('X-DeployCore-Session-Expires')
  if (deadline && response.status !== 204) window.dispatchEvent(new CustomEvent('deploycore:session-expiry', { detail: deadline }))
  if (responseType === 'blob') return await response.blob() as T
  return response.status === 204 ? undefined as T : await response.json() as T
}
