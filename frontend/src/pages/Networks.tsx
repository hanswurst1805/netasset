import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Globe, Plus, Trash2, RefreshCw, ChevronDown, ChevronUp, Server } from 'lucide-react'
import Badge from '../components/Badge'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch('/api/v1/networks' + path, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json', ...opts?.headers },
  })
  if (!res.ok) throw new Error(await res.text())
  if (res.status === 204) return undefined
  return res.json()
}

interface Network {
  id: string
  name: string
  cidr: string
  description: string | null
  exposure_level: string
  color: string | null
  asset_count: number
}

const EXPOSURE_COLORS: Record<string, string> = {
  EXTERN: 'bg-red-900 text-red-300 border-red-700',
  DMZ:    'bg-yellow-900 text-yellow-300 border-yellow-700',
  INTERN: 'bg-blue-900 text-blue-300 border-blue-700',
}

function NetworkRow({ net }: { net: Network }) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)

  const { data: assets = [], isLoading: assetsLoading } = useQuery({
    queryKey: ['network-assets', net.id],
    queryFn: () => apiFetch(`/${net.id}/assets`),
    enabled: open,
  })

  const del = useMutation({
    mutationFn: () => apiFetch(`/${net.id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['networks'] }),
  })

  const expCls = EXPOSURE_COLORS[net.exposure_level] ?? 'bg-gray-800 text-gray-300 border-gray-700'

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      <div className="flex items-center gap-4 px-4 py-3">
        {/* Farb-Indikator */}
        <div className="w-3 h-3 rounded-full shrink-0"
          style={{ background: net.color || '#4b5563' }} />

        {/* Name + CIDR */}
        <div className="flex-1 min-w-0">
          <div className="font-medium text-sm">{net.name}</div>
          <div className="text-xs font-mono text-gray-400 mt-0.5">{net.cidr}</div>
        </div>

        {/* Exposure */}
        {(net as any).gateway_hostname && (
          <span className="text-xs text-yellow-500 font-mono hidden sm:inline">⇄ {(net as any).gateway_hostname}</span>
        )}
        <span className={`text-xs px-2 py-0.5 rounded border font-medium ${expCls}`}>
          {net.exposure_level}
        </span>

        {/* Asset-Count */}
        <button
          onClick={() => setOpen(!open)}
          className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 px-2.5 py-1.5 rounded transition-colors"
        >
          <Server size={12} />
          {net.asset_count} Assets
          {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
        </button>

        {/* Beschreibung */}
        {net.description && (
          <div className="text-xs text-gray-600 max-w-xs truncate hidden lg:block">{net.description}</div>
        )}

        <button
          onClick={() => del.mutate()}
          className="text-gray-600 hover:text-red-400 transition-colors shrink-0"
        >
          <Trash2 size={14} />
        </button>
      </div>

      {/* Asset-Liste aufklappbar */}
      {open && (
        <div className="border-t border-gray-800 p-3">
          {assetsLoading && <div className="text-gray-600 text-xs">Laden…</div>}
          {!assetsLoading && assets.length === 0 && (
            <div className="text-gray-600 text-xs">Keine Assets in diesem Netz</div>
          )}
          <div className="grid grid-cols-2 gap-1.5">
            {assets.map((a: any) => (
              <button
                key={a.id}
                onClick={() => navigate(`/assets/${a.id}`)}
                className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 rounded px-3 py-1.5 text-left transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{a.hostname || '—'}</div>
                  <div className="text-xs text-gray-500 font-mono">{a.ip_address}</div>
                </div>
                <Badge value={a.exposure_level} />
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

async function fetchRouters() {
  const t = localStorage.getItem('token') ?? ''
  const types = ['router', 'firewall']
  const all = await Promise.all(types.map(type =>
    fetch(`/api/v1/assets?asset_type=${type}&limit=100`, {
      headers: { Authorization: `Bearer ${t}` },
    }).then(r => r.json())
  ))
  return all.flat()
}

function NewNetworkForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: routers = [] } = useQuery({ queryKey: ['router-assets'], queryFn: fetchRouters })
  const [form, setForm] = useState({
    name: '', cidr: '', description: '', exposure_level: 'INTERN', color: '#3b82f6',
    gateway_asset_id: '',
  })
  const [error, setError] = useState('')

  const create = useMutation({
    mutationFn: () => apiFetch('', {
      method: 'POST',
      body: JSON.stringify({
        ...form,
        description: form.description || null,
        gateway_asset_id: form.gateway_asset_id || null,
      }),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['networks'] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#6b7280']

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
      <h3 className="font-semibold text-sm flex items-center gap-2"><Globe size={14} /> Neues Netzwerk</h3>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Name *</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="z.B. Heimnetz, Office LAN, Server-VLAN"
            value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">CIDR *</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm font-mono text-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="192.168.178.0/24"
            value={form.cidr} onChange={e => setForm({ ...form, cidr: e.target.value })} />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Exposure</label>
          <select className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.exposure_level} onChange={e => setForm({ ...form, exposure_level: e.target.value })}>
            <option value="INTERN">INTERN</option>
            <option value="DMZ">DMZ</option>
            <option value="EXTERN">EXTERN</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Farbe</label>
          <div className="flex gap-2 mt-1">
            {COLORS.map(c => (
              <button key={c} onClick={() => setForm({ ...form, color: c })}
                className="w-6 h-6 rounded-full border-2 transition-all"
                style={{ background: c, borderColor: form.color === c ? 'white' : 'transparent' }} />
            ))}
          </div>
        </div>
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">
            Gateway-Router (optional)
            <span className="text-gray-600 ml-2 font-normal">Router der dieses Netz nach oben verbindet</span>
          </label>
          <select className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.gateway_asset_id} onChange={e => setForm({ ...form, gateway_asset_id: e.target.value })}>
            <option value="">— kein Gateway —</option>
            {routers.map((r: any) => (
              <option key={r.id} value={r.id}>
                {r.hostname || r.ip_address} ({r.asset_type})
              </option>
            ))}
          </select>
        </div>
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Beschreibung (optional)</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="z.B. Fritz!Box Heimnetz, Büro VLAN 10"
            value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
        </div>
      </div>

      {error && <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>}

      <div className="flex justify-end gap-2">
        <button onClick={onClose} className="text-sm text-gray-400 hover:text-gray-200 px-4 py-2">Abbrechen</button>
        <button onClick={() => create.mutate()}
          disabled={!form.name || !form.cidr || create.isPending}
          className="text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-4 py-2 rounded-lg">
          {create.isPending ? 'Anlegen…' : 'Netzwerk anlegen'}
        </button>
      </div>
    </div>
  )
}

export default function Networks() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)

  const { data: networks = [], isLoading } = useQuery({
    queryKey: ['networks'],
    queryFn: () => apiFetch(''),
  })

  const reclassify = useMutation({
    mutationFn: () => apiFetch('/reclassify', { method: 'POST' }),
    onSuccess: (r: any) => {
      qc.invalidateQueries({ queryKey: ['networks'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      alert(`${r.updated} von ${r.total} Assets neu zugeordnet`)
    },
  })

  const totalAssets = networks.reduce((s: number, n: Network) => s + n.asset_count, 0)

  return (
    <div className="max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe size={22} /> IP-Netzwerke
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Definiere Subnetze — Assets werden automatisch per IP zugeordnet
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => reclassify.mutate()}
            disabled={reclassify.isPending || networks.length === 0}
            className="flex items-center gap-2 text-sm bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-gray-300 px-3 py-2 rounded-lg border border-gray-700"
          >
            <RefreshCw size={13} className={reclassify.isPending ? 'animate-spin' : ''} />
            Neu klassifizieren
          </button>
          <button onClick={() => setShowNew(!showNew)}
            className="flex items-center gap-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg">
            <Plus size={14} /> Netzwerk hinzufügen
          </button>
        </div>
      </div>

      {/* Statistik */}
      {networks.length > 0 && (
        <div className="grid grid-cols-3 gap-3 mb-6">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-indigo-400">{networks.length}</div>
            <div className="text-xs text-gray-500">Netze definiert</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{totalAssets}</div>
            <div className="text-xs text-gray-500">Assets zugeordnet</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {networks.filter((n: Network) => n.asset_count === 0).length}
            </div>
            <div className="text-xs text-gray-500">Netze leer</div>
          </div>
        </div>
      )}

      {showNew && <div className="mb-6"><NewNetworkForm onClose={() => setShowNew(false)} /></div>}

      {isLoading && <div className="text-gray-500">Laden…</div>}
      <div className="space-y-2">
        {networks.map((n: Network) => <NetworkRow key={n.id} net={n} />)}
        {!isLoading && networks.length === 0 && !showNew && (
          <div className="text-center border border-dashed border-gray-700 rounded-lg p-12 text-gray-600 text-sm">
            <Globe size={32} className="mx-auto mb-3 opacity-30" />
            <p>Noch keine Netze definiert</p>
            <p className="text-xs mt-1">Beispiel: "Heimnetz" → 192.168.178.0/24</p>
          </div>
        )}
      </div>
    </div>
  )
}
