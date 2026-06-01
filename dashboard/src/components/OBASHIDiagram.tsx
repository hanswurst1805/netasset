/**
 * OBASHI-Diagramm-Komponente
 *
 * Zeichnet den OBASHI-Baum als Layered-Diagram:
 *   O ─ Owners
 *   B ─ Business
 *   A ─ Application
 *   S ─ System
 *   H ─ Hardware
 *   I ─ Infrastructure
 *
 * Jede Schicht ist eine horizontale Zeile, Nodes sind Boxen,
 * Edges werden als SVG-Linien zwischen den Ebenen gezeichnet.
 */

import { useState, useRef } from 'react'

// ---------------------------------------------------------------------------
// Typen
// ---------------------------------------------------------------------------

interface OBASHINode {
  id: string
  label: string
  sublabel?: string
  layer: string
  meta: Record<string, any>
}

interface OBASHIEdge {
  from_id: string
  to_id: string
}

interface DiagramData {
  process_id: string
  process_name: string
  nodes: OBASHINode[]
  edges: OBASHIEdge[]
}

// ---------------------------------------------------------------------------
// Layer-Konfiguration (OBASHI-Reihenfolge)
// ---------------------------------------------------------------------------

const LAYERS = [
  { id: 'O', label: 'Owners',         color: '#7c3aed', bg: '#1e1033', border: '#6d28d9' },
  { id: 'B', label: 'Business',       color: '#2563eb', bg: '#0f1c3e', border: '#1d4ed8' },
  { id: 'A', label: 'Application',    color: '#059669', bg: '#0c2419', border: '#047857' },
  { id: 'S', label: 'System',         color: '#d97706', bg: '#1f1508', border: '#b45309' },
  { id: 'H', label: 'Hardware',       color: '#ea580c', bg: '#1f0d04', border: '#c2410c' },
  { id: 'I', label: 'Infrastructure', color: '#dc2626', bg: '#1f0808', border: '#b91c1c' },
]

const LAYER_MAP = Object.fromEntries(LAYERS.map(l => [l.id, l]))

// ---------------------------------------------------------------------------
// Node-Komponente
// ---------------------------------------------------------------------------

function Node({
  node,
  x, y, width, height,
  selected,
  onSelect,
}: {
  node: OBASHINode
  x: number; y: number; width: number; height: number
  selected: boolean
  onSelect: () => void
}) {
  const layer = LAYER_MAP[node.layer]
  return (
    <g
      transform={`translate(${x},${y})`}
      onClick={onSelect}
      style={{ cursor: 'pointer' }}
    >
      <rect
        width={width}
        height={height}
        rx={6}
        fill={selected ? layer.color + '40' : layer.bg}
        stroke={selected ? layer.color : layer.border}
        strokeWidth={selected ? 2 : 1}
      />
      <text
        x={width / 2}
        y={height / 2 - (node.sublabel ? 8 : 0)}
        textAnchor="middle"
        dominantBaseline="middle"
        fill={layer.color}
        fontSize={12}
        fontWeight="600"
      >
        {node.label.length > 18 ? node.label.slice(0, 17) + '…' : node.label}
      </text>
      {node.sublabel && (
        <text
          x={width / 2}
          y={height / 2 + 10}
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#9ca3af"
          fontSize={10}
        >
          {node.sublabel.length > 22 ? node.sublabel.slice(0, 21) + '…' : node.sublabel}
        </text>
      )}
    </g>
  )
}

// ---------------------------------------------------------------------------
// Detail-Panel
// ---------------------------------------------------------------------------

function DetailPanel({ node, onClose }: { node: OBASHINode; onClose: () => void }) {
  const layer = LAYER_MAP[node.layer]
  return (
    <div className="absolute right-0 top-0 w-72 bg-gray-900 border rounded-xl p-4 shadow-2xl z-10"
      style={{ borderColor: layer.border }}>
      <div className="flex items-center justify-between mb-3">
        <div>
          <span className="text-xs font-bold px-2 py-0.5 rounded"
            style={{ background: layer.color + '20', color: layer.color }}>
            {layer.id} – {layer.label}
          </span>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-200 text-lg leading-none">×</button>
      </div>
      <h3 className="font-semibold text-gray-100 mb-1">{node.label}</h3>
      {node.sublabel && <p className="text-sm text-gray-400 mb-3">{node.sublabel}</p>}
      <div className="space-y-1.5">
        {Object.entries(node.meta)
          .filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && v.length === 0))
          .map(([k, v]) => (
            <div key={k} className="flex gap-2 text-xs">
              <span className="text-gray-500 shrink-0 w-28">{k.replace(/_/g, ' ')}</span>
              <span className="text-gray-300 break-all">
                {Array.isArray(v)
                  ? v.map((p: any) => `${p.port}/${p.proto}`).join(', ')
                  : String(v)}
              </span>
            </div>
          ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Haupt-Komponente
// ---------------------------------------------------------------------------

const NODE_W = 160
const NODE_H = 52
const NODE_GAP = 16
const ROW_H = 100
const LABEL_W = 120
const PADDING = 24

export default function OBASHIDiagram({ data }: { data: DiagramData }) {
  const [selected, setSelected] = useState<OBASHINode | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  // Nodes nach Layer gruppieren
  const byLayer = Object.fromEntries(LAYERS.map(l => [l.id, [] as OBASHINode[]]))
  data.nodes.forEach(n => {
    if (byLayer[n.layer]) byLayer[n.layer].push(n)
  })

  // Layout berechnen: X-Position jedes Nodes
  const nodePos: Record<string, { x: number; y: number }> = {}
  const maxRowWidth = Math.max(...Object.values(byLayer).map(
    nodes => nodes.length * (NODE_W + NODE_GAP) - NODE_GAP
  ))
  const svgWidth = LABEL_W + PADDING + maxRowWidth + PADDING

  LAYERS.forEach((layer, rowIdx) => {
    const nodes = byLayer[layer.id]
    const rowY = rowIdx * ROW_H + (ROW_H - NODE_H) / 2
    const totalW = nodes.length * (NODE_W + NODE_GAP) - NODE_GAP
    const startX = LABEL_W + PADDING + (maxRowWidth - totalW) / 2

    nodes.forEach((node, i) => {
      nodePos[node.id] = {
        x: startX + i * (NODE_W + NODE_GAP),
        y: rowY,
      }
    })
  })

  const svgHeight = LAYERS.length * ROW_H + 20

  return (
    <div className="relative">
      <svg
        ref={svgRef}
        width="100%"
        viewBox={`0 0 ${svgWidth} ${svgHeight}`}
        style={{ fontFamily: 'system-ui, sans-serif' }}
      >
        {/* Layer-Label-Streifen */}
        {LAYERS.map((layer, i) => (
          <g key={layer.id}>
            <rect
              x={0} y={i * ROW_H}
              width={svgWidth} height={ROW_H}
              fill={layer.bg}
              opacity={0.4}
            />
            <rect
              x={0} y={i * ROW_H}
              width={LABEL_W} height={ROW_H}
              fill={layer.bg}
              opacity={0.8}
            />
            <text
              x={LABEL_W / 2} y={i * ROW_H + ROW_H / 2 - 8}
              textAnchor="middle" dominantBaseline="middle"
              fill={layer.color} fontSize={18} fontWeight="800"
            >
              {layer.id}
            </text>
            <text
              x={LABEL_W / 2} y={i * ROW_H + ROW_H / 2 + 10}
              textAnchor="middle" dominantBaseline="middle"
              fill={layer.color} fontSize={10} opacity={0.7}
            >
              {layer.label}
            </text>
            {/* Trennlinie */}
            <line
              x1={0} y1={i * ROW_H}
              x2={svgWidth} y2={i * ROW_H}
              stroke="#374151" strokeWidth={1}
            />
          </g>
        ))}

        {/* Edges */}
        {data.edges.map((edge, i) => {
          const from = nodePos[edge.from_id]
          const to = nodePos[edge.to_id]
          if (!from || !to) return null
          const x1 = from.x + NODE_W / 2
          const y1 = from.y + NODE_H
          const x2 = to.x + NODE_W / 2
          const y2 = to.y
          const my = (y1 + y2) / 2
          return (
            <path
              key={i}
              d={`M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`}
              fill="none"
              stroke="#4b5563"
              strokeWidth={1.5}
              opacity={0.6}
            />
          )
        })}

        {/* Nodes */}
        {data.nodes.map(node => {
          const pos = nodePos[node.id]
          if (!pos) return null
          return (
            <Node
              key={node.id}
              node={node}
              x={pos.x} y={pos.y}
              width={NODE_W} height={NODE_H}
              selected={selected?.id === node.id}
              onSelect={() => setSelected(selected?.id === node.id ? null : node)}
            />
          )
        })}
      </svg>

      {/* Detail-Panel */}
      {selected && (
        <DetailPanel
          node={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}
