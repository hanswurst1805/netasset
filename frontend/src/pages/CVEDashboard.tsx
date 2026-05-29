import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type ImpactReport } from '../api/client'
import Badge from '../components/Badge'
import { Search, ChevronDown, ChevronUp } from 'lucide-react'

function ImpactPanel({ report }: { report: ImpactReport }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-800 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="font-mono text-indigo-400 text-sm">{report.cve_id}</span>
          <Badge value={report.severity ?? 'UNKNOWN'} />
          {report.cvss_score && (
            <span className="text-xs text-gray-500">CVSS {report.cvss_score}</span>
          )}
          <span className="text-xs text-gray-500">{report.affected_assets.length} betroffene Assets</span>
        </div>
        {open ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
      </button>

      {open && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          <p className="text-sm text-gray-400">{report.description}</p>

          {report.affected_assets.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 uppercase mb-2">Betroffene Assets</div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-xs text-gray-500 border-b border-gray-800">
                    <th className="text-left pb-1">Asset</th>
                    <th className="text-left pb-1">Exposure</th>
                    <th className="text-left pb-1">Paket</th>
                    <th className="text-left pb-1">Risiko</th>
                  </tr>
                </thead>
                <tbody>
                  {report.affected_assets.map(a => (
                    <tr key={a.asset_id} className="border-b border-gray-800">
                      <td className="py-1.5">{a.hostname ?? a.ip_address}</td>
                      <td className="py-1.5"><Badge value={a.exposure_level} /></td>
                      <td className="py-1.5 font-mono text-xs text-gray-400">{a.affected_package} {a.package_version}</td>
                      <td className="py-1.5">
                        <Badge value={a.risk_level} />
                        <span className="text-xs text-gray-500 ml-2">{a.risk_score}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {report.llm_analysis && (
            <div>
              <div className="text-xs text-gray-500 uppercase mb-2">KI-Analyse</div>
              <p className="text-sm text-gray-300 whitespace-pre-wrap bg-gray-800 rounded p-3">{report.llm_analysis}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function CVEDashboard() {
  const [search, setSearch] = useState('')
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null)

  const { data: results = [], isLoading, refetch } = useQuery({
    queryKey: ['cve-search', search],
    queryFn: () => api.cve.search(search || 'critical vulnerability'),
    enabled: true,
  })

  const { data: impact } = useQuery({
    queryKey: ['cve-impact', selectedCVE],
    queryFn: () => api.cve.impact(selectedCVE!),
    enabled: !!selectedCVE,
  })

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">CVE Dashboard</h1>

      <div className="flex gap-3 mb-6">
        <div className="relative flex-1 max-w-lg">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded-md pl-8 pr-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="Semantische CVE-Suche: z.B. openssl buffer overflow..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && refetch()}
          />
        </div>
        <button
          onClick={() => refetch()}
          className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-4 py-1.5 rounded-md transition-colors"
        >
          Suchen
        </button>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* CVE Liste */}
        <div>
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
            {isLoading ? 'Suche läuft…' : `${results.length} CVEs gefunden`}
          </h2>
          <div className="space-y-2">
            {results.map(r => (
              <button
                key={r.cve_id}
                onClick={() => setSelectedCVE(r.cve_id)}
                className={`w-full text-left bg-gray-900 border rounded-lg p-3 transition-colors ${
                  selectedCVE === r.cve_id
                    ? 'border-indigo-500 bg-indigo-950'
                    : 'border-gray-800 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-sm text-indigo-400">{r.cve_id}</span>
                  <div className="flex items-center gap-2">
                    {r.cvss_score && (
                      <span className="text-xs text-gray-500">CVSS {r.cvss_score}</span>
                    )}
                    <Badge value={r.severity ?? 'UNKNOWN'} />
                  </div>
                </div>
                <p className="text-xs text-gray-500 line-clamp-2">{r.description}</p>
                <div className="text-xs text-gray-600 mt-1">Similarity: {(r.similarity * 100).toFixed(0)}%</div>
              </button>
            ))}
          </div>
        </div>

        {/* Impact Panel */}
        <div>
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Impact Report</h2>
          {!selectedCVE && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center text-gray-600 text-sm">
              CVE auswählen für Impact-Analyse
            </div>
          )}
          {selectedCVE && !impact && (
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center text-gray-500 text-sm">
              Analysiere…
            </div>
          )}
          {impact && <ImpactPanel report={impact} />}
        </div>
      </div>
    </div>
  )
}
