import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Bell, Search, Server } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string) {
  const res = await fetch('/api/v1/alerts' + path, { headers: { Authorization: `Bearer ${token()}` } })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

interface AlertRow {
  id: string
  source: string
  asset_id: string | null
  device_uuid: string | null
  device_name: string | null
  severity: string | null
  severity_score: number | null
  threat: string | null
  type_name: string | null
  category: string | null
  resolved: boolean
  occurred_at: string | null
  user_name: string | null
}

const SEV_BADGE: Record<string, string> = {
  HIGH:          'bg-red-900/70 text-red-300 border-red-700',
  MEDIUM:        'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  LOW:           'bg-blue-900/60 text-blue-300 border-blue-700',
  INFORMATIONAL: 'bg-gray-800 text-gray-400 border-gray-700',
  DIAGNOSTIC:    'bg-gray-800 text-gray-500 border-gray-700',
}
const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : '—')

export default function Alerts() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState('')
  const [openOnly, setOpenOnly] = useState(true)

  const { data: rows = [], isLoading } = useQuery<AlertRow[]>({
    queryKey: ['alerts', openOnly],
    queryFn: () => apiFetch(`?limit=500${openOnly ? '&resolved=false' : ''}`),
  })

  const f = filter.trim().toLowerCase()
  const shown = f
    ? rows.filter(r => [r.device_name, r.threat, r.type_name, r.severity].some(v => v?.toLowerCase().includes(f)))
    : rows

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center gap-2 mb-1">
        <Bell className="text-red-400" />
        <h1 className="text-xl font-semibold text-gray-100">Alarme</h1>
      </div>
      <p className="text-gray-500 text-sm mb-4">Sicherheits-Detections (z. B. ESET) über alle Hosts.</p>

      <div className="flex items-center gap-3 mb-4">
        <div className="relative max-w-sm flex-1">
          <Search size={16} className="absolute left-3 top-2.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="Host, Bedrohung, Typ, Schwere…"
            className="w-full pl-9 pr-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-gray-200" />
        </div>
        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input type="checkbox" checked={openOnly} onChange={e => setOpenOnly(e.target.checked)} />
          nur offene
        </label>
      </div>

      {isLoading ? (
        <p className="text-gray-500">Lädt…</p>
      ) : shown.length === 0 ? (
        <p className="text-gray-500">Keine Alarme.</p>
      ) : (
        <div className="border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Schwere</th>
                <th className="px-4 py-2">Host</th>
                <th className="px-4 py-2">Bedrohung</th>
                <th className="px-4 py-2">Typ</th>
                <th className="px-4 py-2 whitespace-nowrap">Zeit</th>
                <th className="px-4 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {shown.map(r => {
                const sev = (r.severity || '').toUpperCase()
                return (
                  <tr key={r.id} className="border-t border-gray-800 hover:bg-gray-800/40">
                    <td className="px-4 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded border ${SEV_BADGE[sev] || 'bg-gray-800 text-gray-400 border-gray-700'}`}>
                        {r.severity || '—'}{r.severity_score != null ? ` · ${r.severity_score}` : ''}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      {r.asset_id ? (
                        <button onClick={() => navigate(`/assets/${r.asset_id}`)} className="flex items-center gap-1 text-indigo-400 hover:text-indigo-300">
                          <Server size={12} /> {r.device_name || '—'}
                        </button>
                      ) : (
                        <span className="text-gray-400">{r.device_name || '—'}</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-gray-200">{r.threat || '—'}</td>
                    <td className="px-4 py-2 text-gray-500 text-xs">{r.type_name || '—'}</td>
                    <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{fmt(r.occurred_at)}</td>
                    <td className="px-4 py-2">
                      {r.resolved
                        ? <span className="text-xs text-emerald-500">behoben</span>
                        : <span className="text-xs text-red-400 font-medium">offen</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
