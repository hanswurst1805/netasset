import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, AlertTriangle, Lightbulb, Shield, ChevronDown, ChevronUp } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''
const BASE = (id: string) => `/api/v1/reports/assets/${id}`

async function fetchReports(assetId: string) {
  const res = await fetch(BASE(assetId), { headers: { Authorization: `Bearer ${token()}` } })
  if (!res.ok) throw new Error('Fehler beim Laden')
  return res.json()
}

async function fetchReport(assetId: string, reportId: string) {
  const res = await fetch(`${BASE(assetId)}/${reportId}`, { headers: { Authorization: `Bearer ${token()}` } })
  if (!res.ok) throw new Error('Fehler beim Laden')
  return res.json()
}

// ---------------------------------------------------------------------------
// Hardening-Score-Ring
// ---------------------------------------------------------------------------

function ScoreRing({ score, label, color }: { score: number; label: string; color: string }) {
  const r = 36
  const circ = 2 * Math.PI * r
  const fill = (score / 100) * circ
  const colorMap: Record<string, string> = {
    green: '#10b981', yellow: '#f59e0b', red: '#ef4444'
  }
  const c = colorMap[color] || '#6b7280'

  return (
    <div className="flex flex-col items-center">
      <svg width={92} height={92} viewBox="0 0 92 92">
        <circle cx={46} cy={46} r={r} fill="none" stroke="#374151" strokeWidth={8} />
        <circle cx={46} cy={46} r={r} fill="none" stroke={c} strokeWidth={8}
          strokeDasharray={`${fill} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 46 46)" />
        <text x={46} y={46} textAnchor="middle" dominantBaseline="middle"
          fill={c} fontSize={20} fontWeight="700">{score}</text>
        <text x={46} y={62} textAnchor="middle" fill="#6b7280" fontSize={10}>/100</text>
      </svg>
      <span className="text-xs font-semibold mt-1" style={{ color: c }}>{label}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Report-Detail-Ansicht
// ---------------------------------------------------------------------------

function ReportDetail({ assetId, reportId }: { assetId: string; reportId: string }) {
  const [warnOpen, setWarnOpen] = useState(true)
  const [suggOpen, setSuggOpen] = useState(false)
  const [portsOpen, setPortsOpen] = useState(false)

  const { data: report } = useQuery({
    queryKey: ['report', assetId, reportId],
    queryFn: () => fetchReport(assetId, reportId),
    enabled: !!reportId,
  })

  if (!report) return <div className="text-gray-600 text-sm">Laden…</div>

  const p = report.parsed_data
  const warnings    = p.warnings || []
  const suggestions = p.suggestions || []
  const ports       = p.listening_ports || []
  const vulnPkgs    = p.vulnerable_packages || []

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start gap-6">
        {p.hardening_index !== null && p.hardening_index !== undefined && (
          <ScoreRing
            score={p.hardening_index}
            label={p.score_label || ''}
            color={p.score_color || 'gray'}
          />
        )}
        <div className="flex-1 space-y-1 text-sm">
          {p.hostname    && <div><span className="text-gray-500 w-28 inline-block">Hostname</span>{p.hostname}</div>}
          {p.os          && <div><span className="text-gray-500 w-28 inline-block">OS</span>{p.os} {p.os_version}</div>}
          {p.kernel      && <div><span className="text-gray-500 w-28 inline-block">Kernel</span>{p.kernel}</div>}
          {p.lynis_version && <div><span className="text-gray-500 w-28 inline-block">Lynis</span>v{p.lynis_version}</div>}
          {p.report_datetime && <div><span className="text-gray-500 w-28 inline-block">Datum</span>{p.report_datetime}</div>}
          <div className="flex gap-4 pt-1 text-xs text-gray-500">
            <span>{p.tests_performed} Tests</span>
            {p.installed_packages > 0 && <span>{p.installed_packages} Pakete</span>}
          </div>
        </div>

        {/* Stats */}
        <div className="flex gap-3 shrink-0">
          <div className="text-center bg-red-950 border border-red-800 rounded-lg px-4 py-3">
            <div className="text-2xl font-bold text-red-400">{warnings.length}</div>
            <div className="text-xs text-red-600">Warnings</div>
          </div>
          <div className="text-center bg-yellow-950 border border-yellow-800 rounded-lg px-4 py-3">
            <div className="text-2xl font-bold text-yellow-400">{suggestions.length}</div>
            <div className="text-xs text-yellow-600">Vorschläge</div>
          </div>
          {vulnPkgs.length > 0 && (
            <div className="text-center bg-orange-950 border border-orange-800 rounded-lg px-4 py-3">
              <div className="text-2xl font-bold text-orange-400">{vulnPkgs.length}</div>
              <div className="text-xs text-orange-600">Vuln. Pkgs</div>
            </div>
          )}
        </div>
      </div>

      {/* Vulnerable Packages */}
      {vulnPkgs.length > 0 && (
        <div className="bg-orange-950 border border-orange-800 rounded-lg p-3">
          <div className="text-xs font-semibold text-orange-400 mb-2 flex items-center gap-2">
            <AlertTriangle size={12} /> Verwundbare Pakete
          </div>
          <div className="flex flex-wrap gap-1">
            {vulnPkgs.map((pkg: any, i: number) => (
              <span key={i} className="text-xs bg-orange-900 text-orange-300 px-2 py-0.5 rounded">
                {pkg.name} {pkg.version}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Warnings */}
      {warnings.length > 0 && (
        <div className="bg-gray-900 border border-red-800/50 rounded-lg overflow-hidden">
          <button
            onClick={() => setWarnOpen(!warnOpen)}
            className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-800 transition-colors"
          >
            <span className="text-sm font-medium text-red-400 flex items-center gap-2">
              <AlertTriangle size={14} /> Warnings ({warnings.length})
            </span>
            {warnOpen ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
          </button>
          {warnOpen && (
            <div className="divide-y divide-gray-800">
              {warnings.map((w: any, i: number) => (
                <div key={i} className="px-4 py-2.5">
                  <div className="flex items-start gap-2">
                    <span className="text-xs font-mono text-red-600 shrink-0 mt-0.5">{w.id}</span>
                    <div>
                      <div className="text-sm text-gray-200">{w.description}</div>
                      {w.detail && <div className="text-xs text-gray-500 mt-0.5">{w.detail}</div>}
                      {w.solution && <div className="text-xs text-blue-400 mt-1">→ {w.solution}</div>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Suggestions */}
      {suggestions.length > 0 && (
        <div className="bg-gray-900 border border-yellow-800/50 rounded-lg overflow-hidden">
          <button
            onClick={() => setSuggOpen(!suggOpen)}
            className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-800 transition-colors"
          >
            <span className="text-sm font-medium text-yellow-400 flex items-center gap-2">
              <Lightbulb size={14} /> Vorschläge ({suggestions.length})
            </span>
            {suggOpen ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
          </button>
          {suggOpen && (
            <div className="divide-y divide-gray-800 max-h-80 overflow-y-auto">
              {suggestions.map((s: any, i: number) => (
                <div key={i} className="px-4 py-2">
                  <div className="flex items-start gap-2">
                    <span className="text-xs font-mono text-yellow-700 shrink-0 mt-0.5">{s.id}</span>
                    <div>
                      <div className="text-sm text-gray-300">{s.description}</div>
                      {s.detail && <div className="text-xs text-gray-500 mt-0.5">{s.detail}</div>}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Listening Ports */}
      {ports.length > 0 && (
        <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
          <button
            onClick={() => setPortsOpen(!portsOpen)}
            className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-gray-800"
          >
            <span className="text-sm font-medium text-gray-300">Listening Ports ({ports.length})</span>
            {portsOpen ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
          </button>
          {portsOpen && (
            <div className="px-4 pb-3 flex flex-wrap gap-1">
              {ports.map((p: any, i: number) => (
                <span key={i} className="text-xs font-mono bg-gray-800 text-gray-400 px-2 py-0.5 rounded">
                  {p.port}/{p.proto}{p.service ? ` (${p.service})` : ''}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptkomponente
// ---------------------------------------------------------------------------

export default function ReportViewer({ assetId }: { assetId: string }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  const { data: reports = [] } = useQuery({
    queryKey: ['reports', assetId],
    queryFn: () => fetchReports(assetId),
  })

  const del = useMutation({
    mutationFn: (id: string) => fetch(`${BASE(assetId)}/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token()}` },
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['reports', assetId] })
      setSelected(null)
    },
  })

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setUploading(true)
    setError('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await fetch(BASE(assetId), {
        method: 'POST',
        headers: { Authorization: `Bearer ${token()}` },
        body: fd,
      })
      if (!res.ok) throw new Error(await res.text())
      const report = await res.json()
      qc.invalidateQueries({ queryKey: ['reports', assetId] })
      setSelected(report.id)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <div className="flex gap-6">
      {/* Liste links */}
      <div className="w-52 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Reports
          </span>
          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-1 text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-2 py-1 rounded"
          >
            <Upload size={11} /> {uploading ? '…' : 'Upload'}
          </button>
          <input ref={fileRef} type="file" className="hidden"
            accept=".dat,.txt,.log,.html,.json"
            onChange={handleUpload} />
        </div>

        {error && <p className="text-xs text-red-400 mb-2">{error}</p>}

        {reports.length === 0 && !uploading && (
          <p className="text-xs text-gray-600">
            Noch keine Reports — Lynis-Report.dat hochladen
          </p>
        )}

        <div className="space-y-1">
          {reports.map((r: any) => {
            const d = new Date(r.created_at)
            const label = d.toLocaleDateString('de', { day: '2-digit', month: '2-digit', year: '2-digit' })
            const isSelected = r.id === selected
            return (
              <button
                key={r.id}
                onClick={() => setSelected(isSelected ? null : r.id)}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs transition-colors group ${
                  isSelected ? 'bg-indigo-600 text-white' : 'hover:bg-gray-800 text-gray-400'
                }`}
              >
                <Shield size={11} className="shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="font-mono">{label}</div>
                  {r.hardening_index !== null && (
                    <div className={`text-xs ${
                      r.hardening_index >= 80 ? 'text-green-400' :
                      r.hardening_index >= 60 ? 'text-yellow-400' : 'text-red-400'
                    }`}>Score: {r.hardening_index}</div>
                  )}
                </div>
                <button
                  onClick={e => { e.stopPropagation(); del.mutate(r.id) }}
                  className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-red-400 transition-all shrink-0"
                >
                  <Trash2 size={11} />
                </button>
              </button>
            )
          })}
        </div>

        <div className="mt-3 text-xs text-gray-700">
          Lynis: <code className="text-gray-600">lynis audit system</code>
          <br />
          Report: <code className="text-gray-600">/var/log/lynis-report.dat</code>
        </div>
      </div>

      {/* Detail rechts */}
      <div className="flex-1 min-w-0">
        {!selected ? (
          <div className="text-gray-600 text-sm py-4">
            Report auswählen oder neuen hochladen
          </div>
        ) : (
          <ReportDetail assetId={assetId} reportId={selected} />
        )}
      </div>
    </div>
  )
}
