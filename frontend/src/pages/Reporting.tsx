import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Shield, Network, Package, Workflow, RefreshCw, Sparkles, AlertTriangle, CheckCircle } from 'lucide-react'
import Badge from '../components/Badge'
import LastSeen from '../components/LastSeen'

const token = () => localStorage.getItem('token') ?? ''

async function fetchReport(type: string) {
  const res = await fetch(`/api/v1/reporting/${type}`, {
    headers: { Authorization: `Bearer ${token()}` },
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

async function fetchSummary(type: string, data: any) {
  const res = await fetch(`/api/v1/reporting/${type}/summary`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ report_type: type, report_data: data }),
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

const RISK_COLORS: Record<string, string> = {
  HIGH:     'text-red-400 bg-red-950 border-red-800',
  MEDIUM:   'text-yellow-400 bg-yellow-950 border-yellow-800',
  LOW:      'text-green-400 bg-green-950 border-green-800',
  KRITISCH: 'text-red-400 bg-red-950 border-red-800',
  HOCH:     'text-orange-400 bg-orange-950 border-orange-800',
  MITTEL:   'text-yellow-400 bg-yellow-950 border-yellow-800',
  NIEDRIG:  'text-green-400 bg-green-950 border-green-800',
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${RISK_COLORS[level] ?? 'text-gray-400 bg-gray-800 border-gray-700'}`}>
      {level}
    </span>
  )
}

function StatCard({ value, label, color = 'text-indigo-400' }: { value: number | string; label: string; color?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  )
}

function SummaryBox({ reportType, reportData }: { reportType: string; reportData: any }) {
  const [show, setShow] = useState(false)
  const summary = useMutation({
    mutationFn: () => fetchSummary(reportType, reportData),
  })

  if (!show) {
    return (
      <button
        onClick={() => { setShow(true); summary.mutate() }}
        className="flex items-center gap-2 text-xs text-indigo-400 hover:text-indigo-300 border border-indigo-800 hover:border-indigo-600 rounded-lg px-3 py-2 transition-colors"
      >
        <Sparkles size={12} /> KI-Zusammenfassung generieren
      </button>
    )
  }

  return (
    <div className="bg-indigo-950 border border-indigo-800 rounded-xl p-4">
      <div className="flex items-center gap-2 text-xs text-indigo-400 mb-2 font-semibold">
        <Sparkles size={12} /> KI-Zusammenfassung
      </div>
      {summary.isPending && (
        <div className="text-gray-500 text-sm animate-pulse">Analysiere…</div>
      )}
      {summary.isError && (
        <div className="text-red-400 text-sm">{(summary.error as Error).message}</div>
      )}
      {summary.data && (
        <p className="text-sm text-gray-200 leading-relaxed">{summary.data.summary}</p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Security Posture
// ---------------------------------------------------------------------------

function SecurityPostureReport() {
  const navigate = useNavigate()
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['report-security-posture'],
    queryFn: () => fetchReport('security-posture'),
    staleTime: 5 * 60_000,
  })

  if (isLoading) return <div className="text-gray-500 py-8 text-center">Lade Report…</div>
  if (!data) return null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">Stand: {new Date(data.generated_at).toLocaleString('de')}</p>
        <div className="flex gap-2">
          <button onClick={() => refetch()} disabled={isFetching}
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200">
            <RefreshCw size={11} className={isFetching ? 'animate-spin' : ''} /> Aktualisieren
          </button>
        </div>
      </div>

      {/* Kennzahlen */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard value={data.total_assets} label="Assets gesamt" />
        <StatCard value={data.cve_summary.HIGH || 0} label="HIGH CVEs" color="text-red-400" />
        <StatCard value={data.cve_summary.MEDIUM || 0} label="MEDIUM CVEs" color="text-yellow-400" />
        <StatCard value={data.stale_assets} label="Nicht gesehen > 24h" color="text-orange-400" />
      </div>

      {/* Exposure-Verteilung */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Exposure</h3>
          <div className="space-y-2">
            {Object.entries(data.by_exposure).map(([level, count]: [string, any]) => (
              <div key={level} className="flex items-center justify-between">
                <Badge value={level} />
                <div className="flex items-center gap-2">
                  <div className="w-24 bg-gray-800 rounded-full h-2">
                    <div className="h-2 rounded-full bg-indigo-500"
                      style={{ width: `${(count / data.total_assets * 100)}%` }} />
                  </div>
                  <span className="text-xs text-gray-400 w-6 text-right">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Asset-Typen</h3>
          <div className="space-y-1.5">
            {Object.entries(data.by_type)
              .sort(([,a]: any, [,b]: any) => b - a)
              .map(([type, count]: [string, any]) => (
                <div key={type} className="flex items-center justify-between text-sm">
                  <span className="text-gray-400">{type}</span>
                  <span className="text-gray-300 font-medium">{count}</span>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Kritische Assets */}
      {data.critical_assets.length > 0 && (
        <div className="bg-red-950/30 border border-red-800/50 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-red-400 mb-3 flex items-center gap-2">
            <AlertTriangle size={14} /> Kritische Extern-Assets mit HIGH CVEs
          </h3>
          <div className="space-y-2">
            {data.critical_assets.map((a: any) => (
              <div key={a.id}
                onClick={() => navigate(`/assets/${a.id}`)}
                className="flex items-center gap-3 bg-gray-900 hover:bg-gray-800 rounded-lg px-3 py-2 cursor-pointer transition-colors">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium">{a.hostname || a.ip_address}</div>
                  <div className="text-xs text-gray-500">{a.asset_type}</div>
                </div>
                <Badge value={a.exposure_level} />
                <RiskBadge level={a.risk_level} />
                <div className="text-xs text-gray-500">{a.cve_count} CVEs</div>
                <LastSeen date={a.last_seen_at} showIcon={false} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top-Risiko-Assets */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800">
          <h3 className="text-sm font-semibold">Top 10 Risiko-Assets</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="text-left px-4 py-2">Asset</th>
              <th className="text-left px-4 py-2">Typ</th>
              <th className="text-left px-4 py-2">Exposure</th>
              <th className="text-left px-4 py-2">Risiko</th>
              <th className="text-left px-4 py-2">CVEs</th>
              <th className="text-left px-4 py-2">Zuletzt</th>
            </tr>
          </thead>
          <tbody>
            {data.top_risk_assets.map((a: any) => (
              <tr key={a.id} onClick={() => navigate(`/assets/${a.id}`)}
                className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition-colors">
                <td className="px-4 py-2 font-medium">{a.hostname || a.ip_address || '—'}</td>
                <td className="px-4 py-2 text-gray-500">{a.asset_type}</td>
                <td className="px-4 py-2"><Badge value={a.exposure_level} /></td>
                <td className="px-4 py-2"><RiskBadge level={a.risk_level} /></td>
                <td className="px-4 py-2 text-gray-400">{a.cve_count}</td>
                <td className="px-4 py-2"><LastSeen date={a.last_seen_at} showIcon={false} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <SummaryBox reportType="security-posture" reportData={{
        total: data.total_assets, stale: data.stale_assets,
        cve: data.cve_summary, critical: data.critical_assets.length,
      }} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Network Exposure
// ---------------------------------------------------------------------------

function NetworkExposureReport() {
  const navigate = useNavigate()
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['report-network-exposure'],
    queryFn: () => fetchReport('network-exposure'),
    staleTime: 5 * 60_000,
  })

  if (isLoading) return <div className="text-gray-500 py-8 text-center">Lade Report…</div>
  if (!data) return null

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <p className="text-xs text-gray-500">Stand: {new Date(data.generated_at).toLocaleString('de')}</p>
        <button onClick={() => refetch()} disabled={isFetching}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200">
          <RefreshCw size={11} className={isFetching ? 'animate-spin' : ''} /> Aktualisieren
        </button>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <StatCard value={data.extern_count} label="EXTERN Assets" color="text-red-400" />
        <StatCard value={data.dmz_count} label="DMZ Assets" color="text-yellow-400" />
        <StatCard value={Object.keys(data.internet_facing_ports).length} label="Ports von Internet erreichbar" color="text-orange-400" />
      </div>

      {/* Häufigste Internet-Ports */}
      {Object.keys(data.internet_facing_ports).length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Häufigste Internet-Ports</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.internet_facing_ports)
              .sort(([,a]: any, [,b]: any) => b - a)
              .map(([port, count]: [string, any]) => (
                <span key={port} className="text-xs bg-gray-800 border border-gray-700 rounded px-3 py-1.5">
                  <span className="font-mono text-indigo-400">{port}</span>
                  <span className="text-gray-500 ml-1.5">×{count}</span>
                </span>
              ))}
          </div>
        </div>
      )}

      {/* Exponierte Assets */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800">
          <h3 className="text-sm font-semibold">Exponierte Assets (nach Risiko)</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="text-left px-4 py-2">Asset</th>
              <th className="text-left px-4 py-2">Zone</th>
              <th className="text-left px-4 py-2">Internet-Ports</th>
              <th className="text-left px-4 py-2">HIGH CVEs</th>
              <th className="text-left px-4 py-2">Risk-Score</th>
            </tr>
          </thead>
          <tbody>
            {data.exposed_assets.map((a: any) => (
              <tr key={a.id} onClick={() => navigate(`/assets/${a.id}`)}
                className="border-b border-gray-800 hover:bg-gray-800 cursor-pointer transition-colors">
                <td className="px-4 py-2 font-medium">{a.hostname || a.ip_address}</td>
                <td className="px-4 py-2"><Badge value={a.exposure_level} /></td>
                <td className="px-4 py-2">
                  <div className="flex gap-1 flex-wrap">
                    {a.internet_ports.slice(0, 5).map((p: number) => (
                      <span key={p} className="font-mono text-xs bg-red-950 text-red-300 border border-red-800 px-1.5 py-0.5 rounded">{p}</span>
                    ))}
                    {a.internet_ports.length > 5 && <span className="text-xs text-gray-500">+{a.internet_ports.length - 5}</span>}
                    {a.internet_ports.length === 0 && <span className="text-xs text-gray-600">—</span>}
                  </div>
                </td>
                <td className="px-4 py-2">
                  {a.high_cve_count > 0
                    ? <span className="text-red-400 font-bold">{a.high_cve_count}</span>
                    : <span className="text-gray-600">0</span>}
                </td>
                <td className="px-4 py-2 font-mono text-gray-400">{a.risk_score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <SummaryBox reportType="network-exposure" reportData={{
        extern: data.extern_count, dmz: data.dmz_count,
        top_ports: data.internet_facing_ports,
        assets: data.exposed_assets.slice(0, 5),
      }} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// SBOM Vulnerabilities
// ---------------------------------------------------------------------------

function SBOMVulnerabilityReport() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['report-sbom-vulnerabilities'],
    queryFn: () => fetchReport('sbom-vulnerabilities'),
    staleTime: 5 * 60_000,
  })

  if (isLoading) return <div className="text-gray-500 py-8 text-center">Lade Report…</div>
  if (!data) return null

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <p className="text-xs text-gray-500">Stand: {new Date(data.generated_at).toLocaleString('de')}</p>
        <button onClick={() => refetch()} disabled={isFetching}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200">
          <RefreshCw size={11} className={isFetching ? 'animate-spin' : ''} /> Aktualisieren
        </button>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <StatCard value={data.total_packages_checked} label="Pakete geprüft" />
        <StatCard value={data.vulnerable_packages} label="Verwundbare Pakete" color="text-red-400" />
        <StatCard value={data.by_severity?.HIGH || 0} label="Kritische Funde" color="text-red-400" />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-800">
          <h3 className="text-sm font-semibold">Verwundbare Pakete (nach Risk-Score)</h3>
        </div>
        {data.findings.length === 0 && (
          <div className="px-4 py-8 text-center text-gray-600 flex items-center justify-center gap-2">
            <CheckCircle size={16} className="text-green-500" /> Keine verwundbaren Pakete gefunden
          </div>
        )}
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-800">
              <th className="text-left px-4 py-2">Paket</th>
              <th className="text-left px-4 py-2">Version</th>
              <th className="text-left px-4 py-2">CVE</th>
              <th className="text-left px-4 py-2">CVSS</th>
              <th className="text-left px-4 py-2">Schwere</th>
              <th className="text-left px-4 py-2">Betroffene Assets</th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f: any, i: number) => (
              <tr key={i} className="border-b border-gray-800">
                <td className="px-4 py-2 font-medium">{f.pkg_name}</td>
                <td className="px-4 py-2 font-mono text-gray-400 text-xs">{f.pkg_version}</td>
                <td className="px-4 py-2 font-mono text-indigo-400 text-xs">{f.cve_id}</td>
                <td className="px-4 py-2 text-gray-400">{f.cvss_score ?? '—'}</td>
                <td className="px-4 py-2"><RiskBadge level={f.severity || f.risk_level} /></td>
                <td className="px-4 py-2">
                  <div className="flex gap-1 flex-wrap">
                    {f.affected_assets.slice(0, 3).map((h: string) => (
                      <span key={h} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{h}</span>
                    ))}
                    {f.affected_assets.length > 3 && (
                      <span className="text-xs text-gray-600">+{f.affected_assets.length - 3}</span>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <SummaryBox reportType="sbom-vulnerabilities" reportData={{
        packages: data.total_packages_checked,
        vulnerable: data.vulnerable_packages,
        severity: data.by_severity,
        top: data.findings.slice(0, 5),
      }} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Process Risk
// ---------------------------------------------------------------------------

function ProcessRiskReport() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['report-process-risk'],
    queryFn: () => fetchReport('process-risk'),
    staleTime: 5 * 60_000,
  })

  if (isLoading) return <div className="text-gray-500 py-8 text-center">Lade Report…</div>
  if (!data) return null

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <p className="text-xs text-gray-500">Stand: {new Date(data.generated_at).toLocaleString('de')}</p>
        <button onClick={() => refetch()} disabled={isFetching}
          className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200">
          <RefreshCw size={11} className={isFetching ? 'animate-spin' : ''} /> Aktualisieren
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <StatCard value={data.process_count} label="Prozesse gesamt" />
        <StatCard value={data.critical_processes} label="Kritisch / Hoch" color="text-red-400" />
      </div>

      <div className="space-y-2">
        {data.findings.map((f: any) => (
          <div key={f.process_id}
            className={`bg-gray-900 border rounded-xl p-4 ${
              f.risk_rating === 'KRITISCH' ? 'border-red-800' :
              f.risk_rating === 'HOCH' ? 'border-orange-800' :
              'border-gray-800'
            }`}>
            <div className="flex items-center gap-3 mb-2">
              <RiskBadge level={f.risk_rating} />
              <span className="font-medium text-sm">{f.process_name}</span>
              <div className="flex gap-1 ml-auto">
                {[1,2,3,4,5].map(i => (
                  <div key={i} className={`w-3 h-2 rounded-sm ${i <= f.criticality ? 'bg-indigo-500' : 'bg-gray-700'}`} />
                ))}
              </div>
              <span className="text-xs text-gray-500">{f.asset_count} Assets</span>
            </div>
            <div className="flex gap-3 text-xs">
              {f.high_count > 0 && <span className="text-red-400 font-bold">{f.high_count} HIGH</span>}
              {f.medium_count > 0 && <span className="text-yellow-400">{f.medium_count} MEDIUM</span>}
              {f.low_count > 0 && <span className="text-green-400">{f.low_count} LOW</span>}
              {f.high_count === 0 && f.medium_count === 0 && f.low_count === 0 &&
                <span className="text-gray-600">Keine CVE-Risiken bekannt</span>}
              {f.top_cves.length > 0 && (
                <span className="text-gray-600 ml-auto font-mono">
                  {f.top_cves[0].cve_id}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      <SummaryBox reportType="process-risk" reportData={{
        processes: data.process_count,
        critical: data.critical_processes,
        top3: data.findings.slice(0, 3),
      }} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptseite
// ---------------------------------------------------------------------------

const TABS = [
  { id: 'security-posture',    icon: Shield,   label: 'Security Posture',    component: SecurityPostureReport },
  { id: 'network-exposure',    icon: Network,  label: 'Netzwerk-Exposure',   component: NetworkExposureReport },
  { id: 'sbom-vulnerabilities',icon: Package,  label: 'SBOM-Vulnerabilities',component: SBOMVulnerabilityReport },
  { id: 'process-risk',        icon: Workflow, label: 'Prozess-Risiko',      component: ProcessRiskReport },
]

export default function Reporting() {
  const [active, setActive] = useState('security-posture')
  const ActiveComponent = TABS.find(t => t.id === active)?.component ?? (() => null)

  return (
    <div className="max-w-5xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Security Reports</h1>
        <p className="text-sm text-gray-500 mt-1">
          Strukturierte Berichte aus deiner CMDB — sofort, ohne Wartezeit
        </p>
      </div>

      {/* Tab-Navigation */}
      <div className="flex gap-1 mb-6 border-b border-gray-800">
        {TABS.map(({ id, icon: Icon, label }) => (
          <button
            key={id}
            onClick={() => setActive(id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm border-b-2 transition-colors whitespace-nowrap ${
              active === id
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Icon size={14} />{label}
          </button>
        ))}
      </div>

      <ActiveComponent />
    </div>
  )
}
