import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Boxes, Search, Server } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string) {
  const res = await fetch('/api/v1/services' + path, {
    headers: { Authorization: `Bearer ${token()}` },
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

interface ServiceRow {
  id: string
  asset_id: string
  hostname: string | null
  ip_address: string | null
  port: number
  proto: string
  bind_address: string | null
  bind_scope: 'localhost' | 'lan' | 'all'
  process_name: string | null
  sbom_pkg: string | null
  container_name: string | null
  container_image: string | null
  source: string | null
}

const SCOPE_BADGE: Record<string, string> = {
  localhost: 'bg-gray-800 text-gray-400 border-gray-700',
  lan:       'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  all:       'bg-red-900/60 text-red-300 border-red-700',
}
const SCOPE_LABEL: Record<string, string> = { localhost: 'nur localhost', lan: 'LAN', all: 'alle Interfaces' }

export default function Containers() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState('')
  const [containerOnly, setContainerOnly] = useState(true)

  const { data: rows = [], isLoading } = useQuery<ServiceRow[]>({
    queryKey: ['services', containerOnly],
    queryFn: () => apiFetch(`?container_only=${containerOnly}`),
  })

  const f = filter.trim().toLowerCase()
  const shown = f
    ? rows.filter(r => [r.hostname, r.ip_address, r.container_image, r.process_name, r.sbom_pkg]
        .some(v => v?.toLowerCase().includes(f)))
    : rows

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center gap-2 mb-1">
        <Boxes className="text-cyan-400" />
        <h1 className="text-xl font-semibold text-gray-100">Container & Dienste</h1>
      </div>
      <p className="text-gray-500 text-sm mb-4">
        Lauschende Dienste über alle Hosts – Docker/Podman-Container und Prozesse mit Port → SBOM-Paket.
      </p>

      <div className="flex items-center gap-3 mb-4">
        <div className="relative max-w-sm flex-1">
          <Search size={16} className="absolute left-3 top-2.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="Host, Image, Prozess, Paket…"
            className="w-full pl-9 pr-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-gray-200" />
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input type="checkbox" checked={containerOnly} onChange={e => setContainerOnly(e.target.checked)} />
          nur Container
        </label>
      </div>

      {isLoading ? (
        <p className="text-gray-500">Lädt…</p>
      ) : shown.length === 0 ? (
        <p className="text-gray-500">Keine Dienste gefunden.</p>
      ) : (
        <div className="border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Host</th>
                <th className="px-4 py-2">Port</th>
                <th className="px-4 py-2">Erreichbarkeit</th>
                <th className="px-4 py-2">Prozess</th>
                <th className="px-4 py-2">SBOM-Paket</th>
                <th className="px-4 py-2">Container</th>
              </tr>
            </thead>
            <tbody>
              {shown.map(r => (
                <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-800/40">
                  <td className="px-4 py-2">
                    <button onClick={() => navigate(`/assets/${r.asset_id}`)}
                      className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300">
                      <Server size={12} /> {r.hostname || r.ip_address || r.asset_id.slice(0, 8)}
                    </button>
                  </td>
                  <td className="px-4 py-2 font-mono text-gray-300">{r.port}/{r.proto}</td>
                  <td className="px-4 py-2">
                    <span className={`text-xs px-2 py-0.5 rounded border ${SCOPE_BADGE[r.bind_scope] || ''}`}>
                      {SCOPE_LABEL[r.bind_scope] || r.bind_scope}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-400 font-mono text-xs">{r.process_name || '—'}</td>
                  <td className="px-4 py-2">
                    {r.sbom_pkg
                      ? <span className="text-xs bg-cyan-900/50 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded">{r.sbom_pkg}</span>
                      : <span className="text-xs text-gray-700">—</span>}
                  </td>
                  <td className="px-4 py-2 text-gray-400 font-mono text-xs">{r.container_image || r.container_name || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
