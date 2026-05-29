import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import Badge from '../components/Badge'
import OBASHIDiagram from '../components/OBASHIDiagram'
import { ChevronDown, ChevronUp, Layers, BarChart2 } from 'lucide-react'

function CriticalityBar({ value }: { value: number }) {
  const colors = ['', 'bg-green-500', 'bg-green-400', 'bg-yellow-400', 'bg-orange-400', 'bg-red-500']
  return (
    <div className="flex gap-0.5">
      {[1,2,3,4,5].map(i => (
        <div key={i} className={`h-2 w-4 rounded-sm ${i <= value ? colors[value] : 'bg-gray-700'}`} />
      ))}
    </div>
  )
}

async function fetchObashi(id: string) {
  const token = localStorage.getItem('token')
  const res = await fetch(`/api/v1/processes/${id}/obashi`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('OBASHI-Daten konnten nicht geladen werden')
  return res.json()
}

type ViewMode = 'risk' | 'obashi'

function ProcessRow({ process }: { process: any }) {
  const [open, setOpen] = useState(false)
  const [view, setView] = useState<ViewMode>('obashi')

  const { data: risk } = useQuery({
    queryKey: ['process-risk', process.id],
    queryFn: () => api.processes.risk(process.id),
    enabled: open && view === 'risk',
  })

  const { data: assets = [] } = useQuery({
    queryKey: ['process-assets', process.id],
    queryFn: () => api.processes.assets(process.id),
    enabled: open && view === 'risk',
  })

  const { data: obashi } = useQuery({
    queryKey: ['obashi', process.id],
    queryFn: () => fetchObashi(process.id),
    enabled: open && view === 'obashi',
  })

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 px-4 py-3 hover:bg-gray-800 transition-colors"
      >
        <div className="flex-1 text-left">
          <div className="font-medium text-sm">{process.name}</div>
          {process.description && (
            <div className="text-xs text-gray-500 mt-0.5 truncate max-w-md">{process.description}</div>
          )}
        </div>
        <div className="flex items-center gap-6 text-xs text-gray-500">
          <div>
            <div className="text-gray-600 mb-1">Kritikalität</div>
            <CriticalityBar value={process.criticality} />
          </div>
          {process.sla_rto_hours && (
            <div>
              <div className="text-gray-600">RTO</div>
              <div>{process.sla_rto_hours}h</div>
            </div>
          )}
        </div>
        {open ? <ChevronUp size={14} className="text-gray-500 shrink-0" /> : <ChevronDown size={14} className="text-gray-500 shrink-0" />}
      </button>

      {open && (
        <div className="border-t border-gray-800">
          {/* View-Toggle */}
          <div className="flex gap-1 px-4 pt-3 pb-0">
            <button
              onClick={() => setView('obashi')}
              className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${
                view === 'obashi'
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              <Layers size={12} /> OBASHI-Diagramm
            </button>
            <button
              onClick={() => setView('risk')}
              className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${
                view === 'risk'
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              <BarChart2 size={12} /> CVE-Risiko
            </button>
          </div>

          {/* OBASHI View */}
          {view === 'obashi' && (
            <div className="p-4">
              {!obashi && (
                <div className="text-gray-500 text-sm py-4 text-center">Lade OBASHI-Daten…</div>
              )}
              {obashi && obashi.nodes.length === 0 && (
                <div className="text-gray-600 text-sm py-4 text-center">
                  Keine Assets diesem Prozess zugeordnet.
                  <br />
                  <span className="text-xs">Assets über Einstellungen → Prozesse zuordnen.</span>
                </div>
              )}
              {obashi && obashi.nodes.length > 0 && (
                <>
                  <div className="text-xs text-gray-500 mb-3 flex items-center gap-4">
                    <span>{obashi.nodes.length} Nodes</span>
                    <span>{obashi.edges.length} Verbindungen</span>
                    <span className="text-gray-600">Klick auf Node für Details</span>
                  </div>
                  <div className="rounded-lg overflow-hidden border border-gray-800">
                    <OBASHIDiagram data={obashi} />
                  </div>
                </>
              )}
            </div>
          )}

          {/* Risk View */}
          {view === 'risk' && (
            <div className="p-4 grid grid-cols-2 gap-6">
              <div>
                <h3 className="text-xs text-gray-500 uppercase mb-3">CVE-Risiko</h3>
                {!risk ? (
                  <div className="text-gray-600 text-sm">Laden…</div>
                ) : (
                  <>
                    <div className="grid grid-cols-3 gap-2 mb-4">
                      {[
                        { label: 'HIGH', count: risk.high_risk_count, color: 'text-red-400' },
                        { label: 'MEDIUM', count: risk.medium_risk_count, color: 'text-yellow-400' },
                        { label: 'LOW', count: risk.low_risk_count, color: 'text-green-400' },
                      ].map(({ label, count, color }) => (
                        <div key={label} className="bg-gray-800 rounded p-3 text-center">
                          <div className={`text-2xl font-bold ${color}`}>{count}</div>
                          <div className="text-xs text-gray-500">{label}</div>
                        </div>
                      ))}
                    </div>
                    {risk.top_cves.length > 0 && (
                      <div className="space-y-1">
                        <div className="text-xs text-gray-600 mb-1">Top CVEs</div>
                        {risk.top_cves.map((c: any) => (
                          <div key={c.cve_id} className="flex items-center justify-between text-xs">
                            <span className="font-mono text-indigo-400">{c.cve_id}</span>
                            <Badge value={c.risk_level} />
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>

              <div>
                <h3 className="text-xs text-gray-500 uppercase mb-3">Assets ({assets.length})</h3>
                <div className="space-y-1.5">
                  {assets.map((a: any) => (
                    <div key={a.asset_id} className="flex items-center justify-between text-sm bg-gray-800 rounded px-3 py-1.5">
                      <div>
                        <span className="font-medium">{a.hostname ?? a.ip_address}</span>
                        <span className="text-xs text-gray-500 ml-2">{a.role}</span>
                      </div>
                      <Badge value={a.exposure_level} />
                    </div>
                  ))}
                  {assets.length === 0 && (
                    <div className="text-gray-600 text-sm">Keine Assets zugeordnet</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Processes() {
  const { data: processes = [], isLoading } = useQuery({
    queryKey: ['processes'],
    queryFn: api.processes.list,
  })

  return (
    <div className="max-w-5xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Business-Prozesse</h1>
        <p className="text-sm text-gray-500 mt-1">
          OBASHI-Struktur: Owners → Business → Application → System → Hardware → Infrastructure
        </p>
      </div>
      {isLoading && <div className="text-gray-500">Laden…</div>}
      <div className="space-y-3">
        {processes.map((p: any) => <ProcessRow key={p.id} process={p} />)}
        {!isLoading && processes.length === 0 && (
          <div className="text-center bg-gray-900 border border-gray-800 rounded-lg p-8 text-gray-500 text-sm">
            Keine Prozesse vorhanden
          </div>
        )}
      </div>
    </div>
  )
}
