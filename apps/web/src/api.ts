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

export function pollEvery(interval: number) {
  return ({ state }: { state: { error: Error | null } }) => {
    const error = state.error
    return error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 429
      ? false : interval
  }
}

export function upload<T>(path: string, file: File, csrf: string, progress: (value: number) => void, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    const abort = () => request.abort()
    request.open('POST', '/api/v1' + path)
    request.responseType = 'json'
    request.setRequestHeader('Content-Type', 'application/octet-stream')
    request.setRequestHeader('X-DeployCore-Request', '1')
    request.setRequestHeader('X-CSRF-Token', csrf)
    request.upload.onprogress = event => {
      if (event.lengthComputable) progress(Math.round(event.loaded / event.total * 100))
    }
    request.onerror = () => reject(new Error('network'))
    request.onabort = () => reject(new DOMException('aborted', 'AbortError'))
    request.onloadend = () => signal.removeEventListener('abort', abort)
    request.onload = () => {
      if (request.status < 200 || request.status >= 300) {
        reject(new ApiError(request.status, typeof request.response?.detail === 'string' ? request.response.detail : ''))
      } else {
        const deadline = request.getResponseHeader('X-DeployCore-Session-Expires')
        if (deadline) window.dispatchEvent(new CustomEvent('deploycore:session-expiry', { detail: deadline }))
        resolve(request.response as T)
      }
    }
    if (signal.aborted) {
      reject(new DOMException('aborted', 'AbortError'))
      return
    }
    signal.addEventListener('abort', abort, { once: true })
    request.send(file)
  })
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
