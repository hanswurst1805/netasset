const BASE = '/api/v1'
const AUTH = '/auth'

// ---------------------------------------------------------------------------
// HTTP-Helper
// ---------------------------------------------------------------------------

function getToken() {
  return localStorage.getItem('token')
}

async function req<T>(path: string, opts?: RequestInit & { auth?: boolean }): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(opts?.headers as Record<string, string>),
  }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch((opts?.auth ? AUTH : BASE) + path, { ...opts, headers })
  if (res.status === 401) {
    localStorage.removeItem('token')
    window.location.href = '/login'
    throw new Error('Nicht authentifiziert')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail ?? `${res.status} ${res.statusText}`)
  }
  return res.json()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Asset {
  id: string
  hostname: string | null
  ip_address: string | null
  fqdn: string | null
  mac_address: string | null
  asset_type: string
  os_name: string | null
  os_version: string | null
  exposure_level: 'INTERN' | 'DMZ' | 'EXTERN'
  open_ports: { port: number; proto: string; reachable_from: string[] }[] | null
  tags: string[] | null
  is_active: boolean
}

export interface SBOMEntry {
  id: number
  asset_id: string
  pkg_name: string
  pkg_version: string
  pkg_type: string | null
  cpe: string | null
  source: string | null
}

export interface CVEResult {
  cve_id: string
  description: string
  cvss_score: number | null
  severity: string | null
  similarity: number
}

export interface AffectedAsset {
  asset_id: string
  hostname: string | null
  ip_address: string | null
  exposure_level: string
  affected_package: string
  package_version: string
  risk_score: number
  risk_level: 'HIGH' | 'MEDIUM' | 'LOW'
}

export interface ImpactReport {
  cve_id: string
  description: string
  cvss_score: number | null
  severity: string | null
  affected_assets: AffectedAsset[]
  llm_analysis: string | null
  business_processes_at_risk: { id: string; name: string; criticality: number }[]
}

export interface Process {
  id: string
  name: string
  criticality: number
  description: string | null
  sla_rto_hours: number | null
  sla_rpo_hours: number | null
}

export interface CVERisk {
  process_id: string
  process_name: string
  criticality: number
  total_affected_assets: number
  high_risk_count: number
  medium_risk_count: number
  low_risk_count: number
  top_cves: { cve_id: string; risk_score: number; risk_level: string }[]
}

export interface User {
  id: string
  username: string
  email: string | null
  role: string
  allowed_tags: string[]
  is_active: boolean
}

export interface APIKey {
  id: string
  name: string
  key_prefix: string
  allowed_tags: string[] | null
  is_active: boolean
  last_used_at: string | null
  raw_key?: string
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const api = {
  auth: {
    login: async (username: string, password: string) => {
      const body = new URLSearchParams({ username, password })
      const res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      if (!res.ok) throw new Error('Login fehlgeschlagen')
      const data = await res.json()
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('role', data.role)
      localStorage.setItem('tags', JSON.stringify(data.allowed_tags))
      return data
    },
    me: () => req<User>('/me', { auth: true }),
    logout: () => { localStorage.clear() },
    users: {
      list: () => req<User[]>('/users', { auth: true }),
      create: (body: object) => req<User>('/users', { auth: true, method: 'POST', body: JSON.stringify(body) }),
      update: (id: string, body: object) => req<User>(`/users/${id}`, { auth: true, method: 'PUT', body: JSON.stringify(body) }),
      delete: (id: string) => req<void>(`/users/${id}`, { auth: true, method: 'DELETE' }),
    },
    apiKeys: {
      list: () => req<APIKey[]>('/apikeys', { auth: true }),
      create: (body: object) => req<APIKey>('/apikeys', { auth: true, method: 'POST', body: JSON.stringify(body) }),
      revoke: (id: string) => req<void>(`/apikeys/${id}`, { auth: true, method: 'DELETE' }),
    },
  },
  assets: {
    list: (params?: Record<string, string>) =>
      req<Asset[]>('/assets?' + new URLSearchParams(params)),
    get: (id: string) => req<Asset>(`/assets/${id}`),
    update: (id: string, body: object) =>
      req<Asset>(`/assets/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    delete: (id: string) =>
      fetch('/api/v1/assets/' + id, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
      }),
  },
  sbom: {
    get: (assetId: string) => req<SBOMEntry[]>(`/sbom/assets/${assetId}/sbom`),
  },
  cve: {
    search: (q: string) => req<CVEResult[]>(`/cve/search?q=${encodeURIComponent(q)}&top_k=20`),
    impact: (cveId: string) => req<ImpactReport>(`/cve/${cveId}/impact?use_llm=false`),
    query: (question: string) =>
      req<{ question: string; answer: string }>('/cve/query', {
        method: 'POST',
        body: JSON.stringify({ question, use_llm: true }),
      }),
  },
  processes: {
    list: () => req<Process[]>('/processes'),
    get: (id: string) => req<Process>(`/processes/${id}`),
    update: (id: string, body: object) => req<Process>(`/processes/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    risk: (id: string) => req<CVERisk>(`/processes/${id}/cve-risk`),
    assets: (id: string) => req<any[]>(`/processes/${id}/assets`),
  },
  owners: {
    list: () => req<Owner[]>('/owners'),
    create: (body: object) => req<Owner>('/owners', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: object) => req<Owner>(`/owners/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    delete: (id: string) => req<void>(`/owners/${id}`, { method: 'DELETE' }),
  },
  applications: {
    list: (processId?: string) => req<AppEntity[]>(`/applications${processId ? '?process_id=' + processId : ''}`),
    create: (body: object) => req<AppEntity>('/applications', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: object) => req<AppEntity>(`/applications/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    delete: (id: string) => req<void>(`/applications/${id}`, { method: 'DELETE' }),
  },
}

export interface Owner {
  id: string
  name: string
  email: string | null
  team: string | null
  department: string | null
  role: string | null
}

export interface AppEntity {
  id: string
  name: string
  description: string | null
  app_type: string | null
  version: string | null
  url: string | null
  process_id: string
  owner_id: string | null
  criticality: number | null
  asset_ids: string[] | null
  is_active: boolean
}
