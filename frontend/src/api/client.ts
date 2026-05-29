const BASE = '/api/v1'

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...opts?.headers },
    ...opts,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

// Types
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

// API calls
export const api = {
  assets: {
    list: (params?: Record<string, string>) =>
      req<Asset[]>('/assets?' + new URLSearchParams(params)),
    get: (id: string) => req<Asset>(`/assets/${id}`),
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
    risk: (id: string) => req<CVERisk>(`/processes/${id}/cve-risk`),
    assets: (id: string) => req<any[]>(`/processes/${id}/assets`),
  },
}
