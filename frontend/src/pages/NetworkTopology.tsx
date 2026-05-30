import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Network, Plus, Trash2, Star } from 'lucide-react'

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
  const res = await fetch('/api/v1/assets?asset_type=router&limit=100', {
    headers: { Authorization: `Bearer ${token()}` },
  })
  const routers = await res.json()
  const res2 = await fetch('/api/v1/assets?asset_type=firewall&limit=100', {
    headers: { Authorization: `Bearer ${token()}` },
  })
  const firewalls = await res2.json()
  const res3 = await fetch('/api/v1/assets?asset_type=switch&limit=100', {
    headers: { Authorization: `Bearer ${token()}` },
  })
  const switches = await res3.json()
  return [...routers, ...firewalls, ...switches]
}

// ---------------------------------------------------------------------------
// Topologie-Diagramm
// ---------------------------------------------------------------------------

const SEGMENT_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  EXTERN:  { bg: '#1f0808', border: '#dc2626', text: '#fca5a5' },
  DMZ:     { bg: '#1f1508', border: '#d97706', text: '#fcd34d' },
  INTERN:  { bg: '#0f1c3e', border: '#2563eb', text: '#93c5fd' },
  MGMT:    { bg: '#0c2419', border: '#059669', text: '#6ee7b7' },
  GUEST:   { bg: '#1e1033', border: '#7c3aed', text: '#c4b5fd' },
  default: { bg: '#1f2937', border: '#4b5563', text: '#d1d5db' },
}

function segColor(seg: string) {
  return SEGMENT_COLORS[seg] ?? SEGMENT_COLORS.default
}

interface TopoNode { id: string; type: string; label: string; exposure?: string }
interface TopoEdge { from_id: string; to_id: string; gateway_name: string; is_primary: boolean; asset_hostname?: string; asset_ip?: string }
interface Topology { nodes: TopoNode[]; edges: TopoEdge[] }

function TopologyDiagram({ topo }: { topo: Topology }) {
  const [hovered, setHovered] = useState<string | null>(null)
  if (!topo.nodes.length) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-600 text-sm">
        Noch keine Gateways konfiguriert — unten hinzufügen
      </div>
    )
  }

  // Layout: Segmente in einer Reihe, gleichmäßig verteilt
  const W = 900
  const NODE_W = 140
  const NODE_H = 60
  const Y = 80
  const spacing = W / (topo.nodes.length + 1)

  const nodePos: Record<string, { x: number; y: number }> = {}
  topo.nodes.forEach((n, i) => {
    nodePos[n.id] = { x: spacing * (i + 1), y: Y }
  })

  return (
    <svg width="100%" viewBox={`0 0 ${W} 220`} style={{ fontFamily: 'system-ui, sans-serif' }}>
      {/* Segment-Knoten */}
      {topo.nodes.map(node => {
        const pos = nodePos[node.id]
        if (!pos) return null
        const col = segColor(node.label)
        return (
          <g key={node.id} transform={`translate(${pos.x - NODE_W/2},${pos.y - NODE_H/2})`}>
            <rect width={NODE_W} height={NODE_H} rx={8}
              fill={col.bg} stroke={col.border} strokeWidth={2} />
            <text x={NODE_W/2} y={NODE_H/2 - 6} textAnchor="middle"
              fill={col.text} fontSize={13} fontWeight="700">
              {node.label}
            </text>
            <text x={NODE_W/2} y={NODE_H/2 + 10} textAnchor="middle"
              fill={col.border} fontSize={9} opacity={0.8}>
              {node.exposure ?? 'Segment'}
            </text>
          </g>
        )
      })}

      {/* Gateway-Kanten */}
      {topo.edges.map((edge, i) => {
        const from = nodePos[edge.from_id]
        const to   = nodePos[edge.to_id]
        if (!from || !to) return null

        const x1 = from.x
        const x2 = to.x
        const y1 = from.y + NODE_H / 2
        const y2 = to.y + NODE_H / 2
        const mx = (x1 + x2) / 2
        const my = y1 + 50 + i * 15  // gestaffelt um Überlappung zu vermeiden
        const isHov = hovered === `edge-${i}`
        const label = edge.asset_hostname || edge.asset_ip || edge.gateway_name

        return (
          <g key={i} onMouseEnter={() => setHovered(`edge-${i}`)}
             onMouseLeave={() => setHovered(null)}>
            {/* Kurve */}
            <path
              d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
              fill="none"
              stroke={edge.is_primary ? '#f59e0b' : '#6b7280'}
              strokeWidth={isHov ? 3 : edge.is_primary ? 2.5 : 1.5}
              strokeDasharray={edge.is_primary ? undefined : '5,3'}
              markerEnd="url(#arrow)"
            />
            {/* Label auf der Kurve */}
            <text fontSize={10} textAnchor="middle" fill={isHov ? '#f3f4f6' : '#9ca3af'}>
              <textPath href={`#path-${i}`} startOffset="50%">
              </textPath>
            </text>
            {/* Einfaches Label in der Mitte */}
            <rect x={mx - 52} y={my - 10} width={104} height={20} rx={4}
              fill={edge.is_primary ? '#451a03' : '#111827'}
              stroke={edge.is_primary ? '#f59e0b' : '#374151'}
              strokeWidth={1} />
            <text x={mx} y={my + 4} textAnchor="middle" fontSize={10}
              fill={edge.is_primary ? '#fbbf24' : '#9ca3af'}>
              {edge.is_primary && '★ '}{label.length > 16 ? label.slice(0, 15) + '…' : label}
            </text>
          </g>
        )
      })}

      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#6b7280" />
        </marker>
      </defs>
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Gateway-Liste + Formular
// ---------------------------------------------------------------------------

const SEGMENTS = ['INTERN', 'DMZ', 'EXTERN', 'MGMT', 'GUEST']

function AddGatewayForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: routerAssets = [] } = useQuery({ queryKey: ['gateway-assets'], queryFn: fetchAssets })
  const [form, setForm] = useState({
    asset_id: '',
    name: '',
    from_segment: 'INTERN',
    to_segment: 'EXTERN',
    is_primary: false,
    description: '',
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
        {/* Asset */}
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Router / Firewall / Switch</label>
          <select className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.asset_id} onChange={e => setForm({ ...form, asset_id: e.target.value })}>
            <option value="">— Asset auswählen —</option>
            {routerAssets.map((a: any) => (
              <option key={a.id} value={a.id}>
                {a.hostname || a.ip_address} ({a.asset_type})
              </option>
            ))}
          </select>
        </div>

        {/* Name */}
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Name</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
            placeholder="z.B. Hauptrouter, DMZ-Firewall, VLAN-Gateway"
            value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        </div>

        {/* Von-Segment */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Von (Quell-Segment)</label>
          {customFrom
            ? <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
                placeholder="z.B. 192.168.178.0/24, VLAN-10"
                value={form.from_segment} onChange={e => setForm({ ...form, from_segment: e.target.value })} />
            : <div className="flex gap-1">
                <select className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={form.from_segment} onChange={e => setForm({ ...form, from_segment: e.target.value })}>
                  {SEGMENTS.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button onClick={() => setCustomFrom(true)} className="text-xs text-gray-500 hover:text-gray-300 px-2">+</button>
              </div>
          }
        </div>

        {/* Zu-Segment */}
        <div>
          <label className="block text-xs text-gray-400 mb-1">Zu (Ziel-Segment)</label>
          {customTo
            ? <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
                placeholder="z.B. 10.0.0.0/8, VLAN-20"
                value={form.to_segment} onChange={e => setForm({ ...form, to_segment: e.target.value })} />
            : <div className="flex gap-1">
                <select className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
                  value={form.to_segment} onChange={e => setForm({ ...form, to_segment: e.target.value })}>
                  {SEGMENTS.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <button onClick={() => setCustomTo(true)} className="text-xs text-gray-500 hover:text-gray-300 px-2">+</button>
              </div>
          }
        </div>

        {/* Primär */}
        <div className="col-span-2 flex items-center gap-2">
          <input type="checkbox" id="primary" checked={form.is_primary}
            onChange={e => setForm({ ...form, is_primary: e.target.checked })} />
          <label htmlFor="primary" className="text-sm text-gray-300 flex items-center gap-1">
            <Star size={12} className="text-yellow-500" /> Primärer Gateway für diese Verbindung
          </label>
        </div>

        {/* Beschreibung */}
        <div className="col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Beschreibung (optional)</label>
          <input className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="z.B. Hauptrouter zur Fritz!Box, Verbindung zum Rechenzentrum"
            value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
        </div>
      </div>

      {error && <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>}

      <div className="flex justify-end gap-2 pt-1">
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

// ---------------------------------------------------------------------------
// Hauptseite
// ---------------------------------------------------------------------------

export default function NetworkTopology() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)

  const { data: gateways = [] } = useQuery({ queryKey: ['gateways'], queryFn: () => apiFetch('') })
  const { data: topo } = useQuery({ queryKey: ['topology'], queryFn: () => apiFetch('/topology') })

  const del = useMutation({
    mutationFn: (id: string) => apiFetch(`/${id}`, { method: 'DELETE' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['gateways'] }); qc.invalidateQueries({ queryKey: ['topology'] }) },
  })

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
        <button onClick={() => setShowNew(!showNew)}
          className="flex items-center gap-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg">
          <Plus size={14} /> Gateway hinzufügen
        </button>
      </div>

      {/* Topologie-Diagramm */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-6">
        <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-4">Netzwerk-Segmente</h2>
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
              {/* Segmente */}
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <span className="text-xs px-2 py-1 rounded font-medium"
                  style={{ background: segColor(gw.from_segment).bg, color: segColor(gw.from_segment).text, border: `1px solid ${segColor(gw.from_segment).border}` }}>
                  {gw.from_segment}
                </span>
                <span className="text-gray-500 text-sm">→</span>
                <span className="text-xs px-2 py-1 rounded font-medium"
                  style={{ background: segColor(gw.to_segment).bg, color: segColor(gw.to_segment).text, border: `1px solid ${segColor(gw.to_segment).border}` }}>
                  {gw.to_segment}
                </span>
              </div>

              {/* Gateway-Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  {gw.is_primary && <Star size={12} className="text-yellow-500 shrink-0" />}
                  <span className="text-sm font-medium truncate">{gw.name}</span>
                </div>
                <div className="text-xs text-gray-500">
                  {gw.asset_hostname || gw.asset_ip || gw.asset_type || '—'}
                </div>
              </div>

              {gw.description && (
                <div className="text-xs text-gray-600 flex-1 min-w-0 truncate">{gw.description}</div>
              )}

              <button onClick={() => del.mutate(gw.id)}
                className="text-gray-600 hover:text-red-400 transition-colors shrink-0">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
          {gateways.length === 0 && !showNew && (
            <div className="text-center border border-dashed border-gray-700 rounded-lg p-8 text-gray-600 text-sm">
              Noch keine Gateways — „Gateway hinzufügen" klicken
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
