/**
 * Hierarchisches Netzwerk-Topologie-Diagramm.
 *
 * Layout:
 *   Level 0: EXTERN-Segmente
 *   Level 1: Routers/Firewalls die EXTERN verbinden
 *   Level 2: DMZ / nächste Segmente
 *   Level 3: Routers/Firewalls die DMZ→INTERN verbinden
 *   Level 4: INTERN-Segmente
 *   Level 5: weitere Routers
 *   Level 6: Sub-Segmente
 */

import { useState } from 'react'

interface TopoNode {
  id: string; type: string; label: string
  exposure?: string; cidr?: string
  asset_count: number; connected: boolean
  asset_id?: string; asset_type?: string; asset_ip?: string
  level: number
}
interface TopoEdge {
  from_id: string; to_id: string; gateway_name: string
  is_primary: boolean; asset_hostname?: string; asset_ip?: string
}
interface Topology { nodes: TopoNode[]; edges: TopoEdge[] }

// Farben
const EXPOSURE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  EXTERN:  { bg: '#1f0808', border: '#dc2626', text: '#fca5a5' },
  DMZ:     { bg: '#1f1508', border: '#d97706', text: '#fcd34d' },
  INTERN:  { bg: '#0f1c3e', border: '#2563eb', text: '#93c5fd' },
  default: { bg: '#1f2937', border: '#4b5563', text: '#d1d5db' },
}
function segColor(exposure?: string) {
  return EXPOSURE_COLORS[exposure || ''] ?? EXPOSURE_COLORS.default
}

const ROUTER_COLOR = { bg: '#1a1200', border: '#f59e0b', text: '#fde68a' }
const FIREWALL_COLOR = { bg: '#1f0a0a', border: '#ef4444', text: '#fca5a5' }

export default function TopologyDiagram({ topo }: { topo: Topology }) {
  const [hovered, setHovered] = useState<string | null>(null)

  if (!topo.nodes.length) {
    return (
      <div className="flex items-center justify-center h-32 text-gray-600 text-sm">
        Keine Netzwerke definiert — IP-Netzwerke anlegen
      </div>
    )
  }

  // ── Layout berechnen ────────────────────────────────────────────────────
  const W = 960
  const ROW_H = 110   // Vertikaler Abstand zwischen Ebenen
  const SEG_W = 150; const SEG_H = 72
  const RTR_W = 155; const RTR_H = 52

  // Nodes nach Level gruppieren
  const byLevel: Record<number, TopoNode[]> = {}
  for (const n of topo.nodes) {
    const l = n.level ?? 0
    if (!byLevel[l]) byLevel[l] = []
    byLevel[l].push(n)
  }
  const levels = Object.keys(byLevel).map(Number).sort((a, b) => a - b)
  const maxLevel = levels[levels.length - 1] ?? 0
  const svgH = (maxLevel + 1) * ROW_H + 80

  // X-Position pro Level gleichmäßig verteilen
  const nodePos: Record<string, { x: number; y: number; w: number; h: number }> = {}
  for (const lv of levels) {
    const nodes = byLevel[lv]
    const spacing = W / (nodes.length + 1)
    nodes.forEach((n, i) => {
      const isRouter = n.type === 'router' || n.type === 'firewall'
      const w = isRouter ? RTR_W : SEG_W
      const h = isRouter ? RTR_H : SEG_H
      nodePos[n.id] = { x: spacing * (i + 1), y: lv * ROW_H + 50, w, h }
    })
  }

  // Level-Labels
  const levelLabel = (lv: number): string => {
    const nodes = byLevel[lv] || []
    const hasRouter = nodes.some(n => n.type === 'router' || n.type === 'firewall')
    const hasExtern = nodes.some(n => n.exposure === 'EXTERN')
    const hasDMZ    = nodes.some(n => n.exposure === 'DMZ')
    const hasIntern = nodes.some(n => n.exposure === 'INTERN')
    if (hasExtern) return 'EXTERN'
    if (hasRouter) return 'ROUTER / FIREWALL'
    if (hasDMZ) return 'DMZ'
    if (hasIntern) return 'INTERN'
    return `Ebene ${lv}`
  }

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${svgH}`}
      style={{ fontFamily: 'system-ui, sans-serif' }}>

      {/* Level-Hintergründe */}
      {levels.map(lv => {
        const nodes = byLevel[lv] || []
        const hasRouter = nodes.some(n => n.type === 'router' || n.type === 'firewall')
        const y = lv * ROW_H + 30
        return (
          <g key={`bg-${lv}`}>
            <rect x={0} y={y} width={W} height={ROW_H - 4}
              fill={hasRouter ? '#0d0d00' : '#111827'} opacity={0.4} rx={0} />
            <text x={8} y={y + 14} fill={hasRouter ? '#b45309' : '#374151'}
              fontSize={9} fontWeight="600">
              {levelLabel(lv)}
            </text>
          </g>
        )
      })}

      {/* Kanten (hinter Nodes) */}
      {topo.edges.map((edge, i) => {
        const from = nodePos[edge.from_id]
        const to   = nodePos[edge.to_id]
        if (!from || !to) return null

        const x1 = from.x
        const y1 = from.y + from.h / 2
        const x2 = to.x
        const y2 = to.y - to.h / 2
        const isHov = hovered === `e${i}`

        return (
          <g key={i}
            onMouseEnter={() => setHovered(`e${i}`)}
            onMouseLeave={() => setHovered(null)}>
            <line x1={x1} y1={y1} x2={x2} y2={y2}
              stroke={edge.is_primary ? '#f59e0b' : '#4b5563'}
              strokeWidth={isHov ? 3 : edge.is_primary ? 2.5 : 1.5}
              strokeDasharray={edge.is_primary ? undefined : '5,3'}
              markerEnd="url(#arr)"
            />
            {isHov && (
              <text x={(x1+x2)/2 + 6} y={(y1+y2)/2}
                fill="#d1d5db" fontSize={10}>
                {edge.asset_hostname || edge.asset_ip || edge.gateway_name}
              </text>
            )}
          </g>
        )
      })}

      {/* Segment-Nodes */}
      {topo.nodes.filter(n => n.type === 'segment').map(node => {
        const pos = nodePos[node.id]
        if (!pos) return null
        const col = segColor(node.exposure)
        const isHov = hovered === node.id
        return (
          <g key={node.id}
            transform={`translate(${pos.x - SEG_W/2},${pos.y - SEG_H/2})`}
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}>
            <rect width={SEG_W} height={SEG_H} rx={8}
              fill={col.bg}
              stroke={isHov ? col.text : col.border}
              strokeWidth={node.connected ? 2 : 1}
              strokeDasharray={node.connected ? undefined : '4,3'}
              opacity={node.connected ? 1 : 0.65} />
            <text x={SEG_W/2} y={22} textAnchor="middle"
              fill={col.text} fontSize={12} fontWeight="700">
              {node.label.length > 16 ? node.label.slice(0,15)+'…' : node.label}
            </text>
            {node.cidr && (
              <text x={SEG_W/2} y={36} textAnchor="middle"
                fill={col.border} fontSize={9} opacity={0.8}>{node.cidr}</text>
            )}
            <text x={SEG_W/2} y={node.cidr ? 52 : 40} textAnchor="middle"
              fill="#6b7280" fontSize={9}>
              {node.asset_count > 0 ? `${node.asset_count} Assets` : 'leer'}
            </text>
          </g>
        )
      })}

      {/* Router/Firewall-Nodes */}
      {topo.nodes.filter(n => n.type === 'router' || n.type === 'firewall').map(node => {
        const pos = nodePos[node.id]
        if (!pos) return null
        const isFirewall = node.type === 'firewall'
        const col = isFirewall ? FIREWALL_COLOR : ROUTER_COLOR
        const isHov = hovered === node.id
        return (
          <g key={node.id}
            transform={`translate(${pos.x - RTR_W/2},${pos.y - RTR_H/2})`}
            onMouseEnter={() => setHovered(node.id)}
            onMouseLeave={() => setHovered(null)}>
            {/* Glow */}
            <rect width={RTR_W + 6} height={RTR_H + 6} rx={10}
              fill="none" stroke={col.border} strokeWidth={1}
              opacity={0.25} transform="translate(-3,-3)" />
            <rect width={RTR_W} height={RTR_H} rx={8}
              fill={col.bg} stroke={col.border}
              strokeWidth={isHov ? 3 : 2.5} />
            <text x={18} y={RTR_H/2 + 5} fill={col.border} fontSize={18}>
              {isFirewall ? '🛡' : '⇄'}
            </text>
            <text x={36} y={RTR_H/2 - 5} fill={col.text}
              fontSize={11} fontWeight="700">
              {node.label.length > 15 ? node.label.slice(0,14)+'…' : node.label}
            </text>
            <text x={36} y={RTR_H/2 + 10} fill="#6b7280" fontSize={9}>
              {node.asset_ip || node.asset_type}
            </text>
          </g>
        )
      })}

      <defs>
        <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#6b7280" />
        </marker>
      </defs>
    </svg>
  )
}
