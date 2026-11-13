const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

export interface ApiErrorBody {
  code?: string
  message?: string
  requestId?: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code?: string
  readonly requestId?: string

  constructor(status: number, body: ApiErrorBody) {
    super(body.message || `请求失败: ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = body.code
    this.requestId = body.requestId
  }
}

interface RequestOptions {
  method?: string
  body?: unknown
}

export interface SSEEvent {
  type: string
  message: string
  data?: Record<string, unknown>
  timestamp?: string
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrfToken = readCookie('sophon_csrf')
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken
    }
  }

  let body: string | undefined
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.body)
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    credentials: 'include',
    headers,
    body,
  })

  if (!response.ok) {
    let body: ApiErrorBody = {}
    try {
      body = (await response.json()) as ApiErrorBody
    } catch {
      body = {}
    }
    throw new ApiError(response.status, body)
  }

  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

export function apiGet<T>(path: string): Promise<T> {
  return apiRequest<T>(path)
}

export function apiPost<T>(path: string, body?: unknown): Promise<T> {
  return apiRequest<T>(path, {
    method: 'POST',
    body,
  })
}

export function apiPut<T>(path: string, body?: unknown): Promise<T> {
  return apiRequest<T>(path, {
    method: 'PUT',
    body,
  })
}

export async function apiTextPut<T>(
  path: string,
  body: string,
  headers: Record<string, string> = {},
): Promise<T> {
  const requestHeaders: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'text/plain; charset=utf-8',
    ...headers,
  }
  const csrfToken = readCookie('sophon_csrf')
  if (csrfToken) {
    requestHeaders['X-CSRF-Token'] = csrfToken
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'PUT',
    credentials: 'include',
    headers: requestHeaders,
    body,
  })
  if (!response.ok) {
    let errorBody: ApiErrorBody = {}
    try {
      errorBody = (await response.json()) as ApiErrorBody
    } catch {
      errorBody = {}
    }
    throw new ApiError(response.status, errorBody)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

export function apiDelete<T = void>(path: string): Promise<T> {
  return apiRequest<T>(path, {
    method: 'DELETE',
  })
}

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`
}

export async function apiUpload<T>(path: string, file: File): Promise<T> {
  const form = new FormData()
  form.append('file', file)
  const headers: Record<string, string> = {
    Accept: 'application/json',
  }
  const csrfToken = readCookie('sophon_csrf')
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: form,
  })
  if (!response.ok) {
    let errorBody: ApiErrorBody = {}
    try {
      errorBody = (await response.json()) as ApiErrorBody
    } catch {
      errorBody = {}
    }
    throw new ApiError(response.status, errorBody)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

export async function* apiStream(
  path: string,
  body: unknown,
  signal?: AbortSignal,
): AsyncGenerator<SSEEvent, void, void> {
  const headers: Record<string, string> = {
    Accept: 'text/event-stream',
    'Content-Type': 'application/json',
  }
  const csrfToken = readCookie('sophon_csrf')
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: JSON.stringify(body),
    signal,
  })
  if (!response.ok) {
    let errorBody: ApiErrorBody = {}
    try {
      errorBody = (await response.json()) as ApiErrorBody
    } catch {
      errorBody = {}
    }
    throw new ApiError(response.status, errorBody)
  }
  if (!response.body) {
    throw new Error('浏览器不支持流式响应')
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() || ''
    for (const line of lines) {
      if (!line.startsWith('data: ')) {
        continue
      }
      const raw = line.slice(6).trim()
      if (!raw) {
        continue
      }
      yield JSON.parse(raw) as SSEEvent
    }
  }

  buffer += decoder.decode()
  for (const line of buffer.split('\n')) {
    if (!line.startsWith('data: ')) {
      continue
    }
    const raw = line.slice(6).trim()
    if (raw) {
      yield JSON.parse(raw) as SSEEvent
    }
  }
}

function readCookie(name: string): string {
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const item = part.trim()
    if (item.startsWith(prefix)) {
      return decodeURIComponent(item.slice(prefix.length))
    }
  }
  return ''
}
