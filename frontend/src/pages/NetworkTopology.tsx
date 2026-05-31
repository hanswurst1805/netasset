import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Network, Plus, Trash2, Star, Wand2 } from 'lucide-react'
import TopologyDiagram from '../components/TopologyDiagram'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch('/api/v1/gateways' + path, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json', ...opts?.headers },
  })
  if (!res.ok) throw new Error(await res.text())
  if (res.status === 204) return undefined
  return res.json()
}

async function fetchAssets() {
  const types = ['router', 'firewall', 'switch']
  const all = await Promise.all(types.map(t =>
    fetch(`/api/v1/assets?asset_type=${t}&limit=100`, {
      headers: { Authorization: `Bearer ${token()}` },
    }).then(r => r.json())
  ))
  return all.flat()
}


const SEGMENT_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  EXTERN:  { bg: '#1f0808', border: '#dc2626', text: '#fca5a5' },
  DMZ:     { bg: '#1f1508', border: '#d97706', text: '#fcd34d' },
  INTERN:  { bg: '#0f1c3e', border: '#2563eb', text: '#93c5fd' },
  MGMT:    { bg: '#0c2419', border: '#059669', text: '#6ee7b7' },
  GUEST:   { bg: '#1e1033', border: '#7c3aed', text: '#c4b5fd' },
  default: { bg: '#1f2937', border: '#4b5563', text: '#d1d5db' },
}
function segColor(label: string) {
  return SEGMENT_COLORS[label.toUpperCase()] ?? SEGMENT_COLORS.default
}

// ---------------------------------------------------------------------------
// Gateway-Formular + Hauptseite
// ---------------------------------------------------------------------------

const SEGMENTS = ['INTERN', 'DMZ', 'EXTERN', 'MGMT', 'GUEST']

function AddGatewayForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: routerAssets = [] } = useQuery({ queryKey: ['gateway-assets'], queryFn: fetchAssets })
  const [form, setForm] = useState({
    asset_id: '', name: '', from_segment: 'INTERN', to_segment: 'EXTERN',
    is_primary: false, description: '',
  })
  const [customFrom, setCustomFrom] = useState(false)
  const [customTo, setCustomTo] = useState(false)
  const [error, setError] = useState('')

  const create = useMutation({
    mutationFn: () => apiFetch('', { method: 'POST', body: JSON.stringify({ ...form, description: form.description || null }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['gateways'] }); qc.invalidateQueries({ queryKey: ['topology'] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
      <h3 className="font-semibold text-sm flex items-center gap-2"><Network size={14} /> Neues Gateway</h3>

      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Router / Firewall / Switch</label>
          <select className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.asset_id} onChange={e => setForm({ ...form, asset_id: e.target.value })}>
            <option value="">— Asset auswählen —</option>
            {routerAssets.map((a: any) => (
              <option key={a.id} value={a.id}>{a.hostname || a.ip_address} ({a.asset_type})</option>
            ))}
          </select>
        </div>
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Name</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
            placeholder="z.B. Hauptrouter, DMZ-Firewall"
            value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Von</label>
          {customFrom
            ? <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
                value={form.from_segment} onChange={e => setForm({ ...form, from_segment: e.target.value })} />
            : <div className="flex gap-1">
                <select className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={form.from_segment} onChange={e => setForm({ ...form, from_segment: e.target.value })}>
                  {SEGMENTS.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button onClick={() => setCustomFrom(true)} className="text-xs text-gray-500 hover:text-gray-300 px-2">+</button>
              </div>}
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Zu</label>
          {customTo
            ? <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
                value={form.to_segment} onChange={e => setForm({ ...form, to_segment: e.target.value })} />
            : <div className="flex gap-1">
                <select className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={form.to_segment} onChange={e => setForm({ ...form, to_segment: e.target.value })}>
                  {SEGMENTS.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button onClick={() => setCustomTo(true)} className="text-xs text-gray-500 hover:text-gray-300 px-2">+</button>
              </div>}
        </div>
        <div className="col-span-2 flex items-center gap-2">
          <input type="checkbox" id="primary" checked={form.is_primary}
            onChange={e => setForm({ ...form, is_primary: e.target.checked })} />
          <label htmlFor="primary" className="text-sm text-gray-300 flex items-center gap-1">
            <Star size={12} className="text-yellow-500" /> Primärer Gateway
          </label>
        </div>
      </div>

      {error && <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>}

      <div className="flex justify-end gap-2">
        <button onClick={onClose} className="text-sm text-gray-400 hover:text-gray-200 px-4 py-2">Abbrechen</button>
        <button onClick={() => create.mutate()}
          disabled={!form.asset_id || !form.name || create.isPending}
          className="text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-4 py-2 rounded-lg">
          {create.isPending ? 'Anlegen…' : 'Gateway anlegen'}
        </button>
      </div>
    </div>
  )
}

export default function NetworkTopology() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)

  const { data: gateways = [] } = useQuery({ queryKey: ['gateways'], queryFn: () => apiFetch('') })
  const { data: topo } = useQuery({ queryKey: ['topology'], queryFn: () => apiFetch('/topology') })

  const del = useMutation({
    mutationFn: (id: string) => apiFetch(`/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['gateways'] }); qc.invalidateQueries({ queryKey: ['topology'] }) },
  })

  const autoDetect = useMutation({
    mutationFn: () => apiFetch('/auto-detect', { method: 'POST' }),
    onSuccess: (r: any) => {
      qc.invalidateQueries({ queryKey: ['gateways'] })
      qc.invalidateQueries({ queryKey: ['topology'] })
      alert(`${r.created} Gateways automatisch erkannt, ${r.skipped} bereits vorhanden`)
    },
    onError: (e: Error) => alert(`Fehler: ${e.message}`),
  })

  const connectedCount = (topo?.nodes ?? []).filter((n: any) => n.connected).length
  const isolatedCount  = (topo?.nodes ?? []).filter((n: any) => !n.connected).length

  return (
    <div className="max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Network size={22} /> Netzwerk-Topologie
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Router und Firewalls als Gateways zwischen Netzwerksegmenten
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => autoDetect.mutate()}
            disabled={autoDetect.isPending}
            className="flex items-center gap-2 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-gray-200 px-3 py-2 rounded-lg border border-gray-600"
            title="Gateways aus Router/Firewall-Assets mit mehreren Netzwerk-Zonen automatisch erkennen"
          >
            <Wand2 size={14} /> {autoDetect.isPending ? 'Erkenne…' : 'Auto-Erkennen'}
          </button>
          <button onClick={() => setShowNew(!showNew)}
            className="flex items-center gap-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg">
            <Plus size={14} /> Gateway hinzufügen
          </button>
        </div>
      </div>

      {/* Diagramm */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Netzwerk-Segmente</h2>
          <div className="flex gap-3 text-xs text-gray-600">
            {connectedCount > 0 && <span>{connectedCount} verbunden</span>}
            {isolatedCount > 0 && <span className="text-gray-700">{isolatedCount} isoliert</span>}
          </div>
        </div>
        {topo ? <TopologyDiagram topo={topo} /> : <div className="text-gray-600 text-sm py-8 text-center">Laden…</div>}

      </div>

      {/* Formular */}
      {showNew && <div className="mb-6"><AddGatewayForm onClose={() => setShowNew(false)} /></div>}

      {/* Gateway-Liste */}
      <div>
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
          Konfigurierte Gateways ({gateways.length})
        </h2>
        <div className="space-y-2">
          {gateways.map((gw: any) => (
            <div key={gw.id} className="flex items-center gap-4 bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <span className="text-xs px-2 py-1 rounded font-medium border"
                  style={{ background: segColor(gw.from_segment).bg, color: segColor(gw.from_segment).text, borderColor: segColor(gw.from_segment).border }}>
                  {gw.from_segment}
                </span>
                <span className="text-gray-500 text-sm">→</span>
                <span className="text-xs px-2 py-1 rounded font-medium border"
                  style={{ background: segColor(gw.to_segment).bg, color: segColor(gw.to_segment).text, borderColor: segColor(gw.to_segment).border }}>
                  {gw.to_segment}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  {gw.is_primary && <Star size={12} className="text-yellow-500 shrink-0" />}
                  <span className="text-sm font-medium truncate">{gw.name}</span>
                </div>
                <div className="text-xs text-gray-500">{gw.asset_hostname || gw.asset_ip}</div>
              </div>
              {gw.description && <div className="text-xs text-gray-600 flex-1 truncate hidden lg:block">{gw.description}</div>}
              <button onClick={() => del.mutate(gw.id)} className="text-gray-600 hover:text-red-400 transition-colors shrink-0">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
          {gateways.length === 0 && !showNew && (
            <div className="text-center border border-dashed border-gray-700 rounded-lg p-6 text-gray-600 text-sm">
              Noch keine Gateways — „Auto-Erkennen" oder „Gateway hinzufügen" klicken
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
