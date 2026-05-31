import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Network, Plus, Trash2, Star, Wand2 } from 'lucide-react'

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

// ---------------------------------------------------------------------------
// Farben pro Exposure/Segment-Name
// ---------------------------------------------------------------------------

const SEGMENT_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  EXTERN:  { bg: '#1f0808', border: '#dc2626', text: '#fca5a5' },
  DMZ:     { bg: '#1f1508', border: '#d97706', text: '#fcd34d' },
  INTERN:  { bg: '#0f1c3e', border: '#2563eb', text: '#93c5fd' },
  MGMT:    { bg: '#0c2419', border: '#059669', text: '#6ee7b7' },
  GUEST:   { bg: '#1e1033', border: '#7c3aed', text: '#c4b5fd' },
  default: { bg: '#1f2937', border: '#4b5563', text: '#d1d5db' },
}

function segColor(label: string) {
  const exp = label.toUpperCase()
  return SEGMENT_COLORS[exp] ?? SEGMENT_COLORS.default
}

// ---------------------------------------------------------------------------
// Topologie-Diagramm
// ---------------------------------------------------------------------------

interface TopoNode {
  id: string; type: string; label: string; exposure?: string; cidr?: string
  asset_count: number; connected: boolean
  asset_id?: string; asset_type?: string; asset_ip?: string
}
interface TopoEdge {
  from_id: string; to_id: string; gateway_name: string
  is_primary: boolean; asset_hostname?: string; asset_ip?: string
}
interface Topology { nodes: TopoNode[]; edges: TopoEdge[] }

function TopologyDiagram({ topo }: { topo: Topology }) {
  const [hovered, setHovered] = useState<string | null>(null)

  if (!topo.nodes.length) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-600 text-sm">
        Keine Netzwerke definiert — zuerst IP-Netzwerke anlegen
      </div>
    )
  }

  // Nodes nach Typ trennen
  const segments = topo.nodes.filter(n => n.type === 'segment')
  const routers  = topo.nodes.filter(n => n.type === 'router' || n.type === 'firewall')
  const connectedSegs = segments.filter(n => n.connected)
  const isolatedSegs  = segments.filter(n => !n.connected)

  const W = 900
  const SEG_W = 150; const SEG_H = 70
  const RTR_W = 140; const RTR_H = 50
  const Y_SEG = 70        // Segmente oben
  const Y_RTR = 190       // Router Mitte
  const Y_ISO = 310       // Isolierte Segmente unten

  const nodePos: Record<string, { x: number; y: number }> = {}

  const segSpacing = W / (connectedSegs.length + 1)
  connectedSegs.forEach((n, i) => { nodePos[n.id] = { x: segSpacing * (i + 1), y: Y_SEG } })

  const rtrSpacing = W / (routers.length + 1)
  routers.forEach((n, i) => { nodePos[n.id] = { x: rtrSpacing * (i + 1), y: Y_RTR } })

  const isoSpacing = W / (isolatedSegs.length + 1)
  isolatedSegs.forEach((n, i) => { nodePos[n.id] = { x: isoSpacing * (i + 1), y: Y_ISO } })

  const svgH = isolatedSegs.length > 0 ? 400 : (routers.length > 0 ? 280 : 180)

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${svgH}`} style={{ fontFamily: 'system-ui, sans-serif' }}>
      {/* Trennlinien */}
      {routers.length > 0 && (
        <text x={10} y={Y_SEG - 12} fill="#4b5563" fontSize={9} fontWeight="600">SEGMENTE</text>
      )}
      {routers.length > 0 && (
        <text x={10} y={Y_RTR - 12} fill="#f59e0b" fontSize={9} fontWeight="600">ROUTER / FIREWALLS</text>
      )}
      {isolatedSegs.length > 0 && (
        <>
          <line x1={20} y1={Y_ISO - 18} x2={W-20} y2={Y_ISO - 18}
            stroke="#374151" strokeWidth={1} strokeDasharray="4,4"/>
          <text x={10} y={Y_ISO - 8} fill="#4b5563" fontSize={9}>ISOLIERT</text>
        </>
      )}

      {/* Kanten HINTER den Nodes zeichnen */}
      {topo.edges.map((edge, i) => {
        const from = nodePos[edge.from_id]
        const to   = nodePos[edge.to_id]
        if (!from || !to) return null

        const fromIsRouter = edge.from_id.startsWith('router-')
        const toIsRouter   = edge.to_id.startsWith('router-')
        const x1 = from.x
        const y1 = from.y + (fromIsRouter ? RTR_H/2 : SEG_H/2)
        const x2 = to.x
        const y2 = to.y - (toIsRouter ? RTR_H/2 : 0) + (toIsRouter ? 0 : SEG_H/2)
        const isHov = hovered === `edge-${i}`
        const isPrimary = edge.is_primary

        return (
          <g key={i} onMouseEnter={() => setHovered(`edge-${i}`)} onMouseLeave={() => setHovered(null)}>
            <line x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={isPrimary ? '#f59e0b' : '#4b5563'}
              strokeWidth={isHov ? 3 : isPrimary ? 2.5 : 1.5}
              strokeDasharray={isPrimary ? undefined : '5,3'}
              markerEnd="url(#arrow)"
            />
            {isHov && (
              <text x={(x1+x2)/2} y={(y1+y2)/2 - 6} textAnchor="middle"
                fill="#9ca3af" fontSize={9}>
                {edge.asset_hostname || edge.asset_ip || edge.gateway_name}
              </text>
            )}
          </g>
        )
      })}

      {/* Segment-Nodes */}
      {[...connectedSegs, ...isolatedSegs].map(node => {
        const pos = nodePos[node.id]
        if (!pos) return null
        const col = segColor(node.label)
        const isHov = hovered === node.id
        return (
          <g key={node.id}
            transform={`translate(${pos.x - SEG_W/2},${pos.y - SEG_H/2})`}
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}
          >
            <rect width={SEG_W} height={SEG_H} rx={8}
              fill={col.bg} stroke={isHov ? col.text : col.border}
              strokeWidth={node.connected ? 2 : 1}
              strokeDasharray={node.connected ? undefined : '4,3'}
              opacity={node.connected ? 1 : 0.7} />
            <text x={SEG_W/2} y={20} textAnchor="middle" fill={col.text} fontSize={12} fontWeight="700">
              {node.label.length > 16 ? node.label.slice(0,15)+'…' : node.label}
            </text>
            {node.cidr && (
              <text x={SEG_W/2} y={34} textAnchor="middle" fill={col.border} fontSize={9} opacity={0.8}>
                {node.cidr}
              </text>
            )}
            <text x={SEG_W/2} y={node.cidr ? 50 : 40} textAnchor="middle" fill="#6b7280" fontSize={9}>
              {node.asset_count > 0 ? `${node.asset_count} Assets` : 'leer'}
            </text>
          </g>
        )
      })}

      {/* Router-Nodes (prominent, goldener Rahmen) */}
      {routers.map(node => {
        const pos = nodePos[node.id]
        if (!pos) return null
        const isFirewall = node.type === 'firewall'
        const isHov = hovered === node.id
        return (
          <g key={node.id}
            transform={`translate(${pos.x - RTR_W/2},${pos.y - RTR_H/2})`}
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}
          >
            {/* Äußerer Glow-Effekt */}
            <rect width={RTR_W} height={RTR_H} rx={8}
              fill="none"
              stroke={isFirewall ? '#ef4444' : '#f59e0b'}
              strokeWidth={isHov ? 4 : 3}
              opacity={0.3}
              transform="translate(-3,-3) scale(1.04,1.08)" />
            <rect width={RTR_W} height={RTR_H} rx={8}
              fill={isFirewall ? '#1f0a0a' : '#1a1200'}
              stroke={isFirewall ? '#ef4444' : '#f59e0b'}
              strokeWidth={isHov ? 3 : 2} />
            {/* Icon-Text */}
            <text x={16} y={28} fill={isFirewall ? '#ef4444' : '#f59e0b'} fontSize={16}>
              {isFirewall ? '🛡' : '⇄'}
            </text>
            <text x={34} y={20} fill={isFirewall ? '#fca5a5' : '#fde68a'} fontSize={11} fontWeight="700">
              {node.label.length > 14 ? node.label.slice(0,13)+'…' : node.label}
            </text>
            <text x={34} y={34} fill="#6b7280" fontSize={9}>
              {node.asset_ip || node.asset_type}
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
        const y1 = from.y + SEG_H / 2
        const y2 = to.y + SEG_H / 2
        const mx = (x1 + x2) / 2
        const drop = 40 + (i % 3) * 15
        const my = y1 + drop
        const isHov = hovered === `edge-${i}`
        const label = edge.asset_hostname || edge.asset_ip || edge.gateway_name

        return (
          <g key={i}
            onMouseEnter={() => setHovered(`edge-${i}`)}
            onMouseLeave={() => setHovered(null)}
          >
            <path
              d={`M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`}
              fill="none"
              stroke={edge.is_primary ? '#f59e0b' : '#6b7280'}
              strokeWidth={isHov ? 3 : edge.is_primary ? 2.5 : 1.5}
              strokeDasharray={edge.is_primary ? undefined : '5,3'}
              markerEnd="url(#arrow)"
            />
            {isHov && (
              <>
                <rect x={mx - 55} y={my - 11} width={110} height={20} rx={4}
                  fill="#111827" stroke={edge.is_primary ? '#f59e0b' : '#4b5563'} strokeWidth={1} />
                <text x={mx} y={my + 4} textAnchor="middle" fontSize={10}
                  fill={edge.is_primary ? '#fbbf24' : '#9ca3af'}>
                  {edge.is_primary ? '★ ' : ''}{label.length > 18 ? label.slice(0,17)+'…' : label}
                </text>
              </>
            )}
            {!isHov && (
              <text x={mx} y={my - 4} textAnchor="middle" fontSize={9}
                fill={edge.is_primary ? '#d97706' : '#6b7280'}>
                {edge.is_primary ? '★' : ''}
              </text>
            )}
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
// Gateway-Formular + Hauptseite (wie bisher, mit Auto-Detect)
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

  const connectedCount = (topo?.nodes ?? []).filter((n: TopoNode) => n.connected).length
  const isolatedCount  = (topo?.nodes ?? []).filter((n: TopoNode) => !n.connected).length

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
