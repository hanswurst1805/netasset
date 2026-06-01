import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type Asset } from '../api/client'
import Badge from '../components/Badge'
import { ArrowLeft, Package, Network, Pencil, Trash2, X, Check, History, FileText, CreditCard } from 'lucide-react'
import LastSeen from '../components/LastSeen'
import SnapshotTimeline from '../components/SnapshotTimeline'
import ReportViewer from '../components/ReportViewer'

// ---------------------------------------------------------------------------
// Tag-Eingabe
// ---------------------------------------------------------------------------

function TagInput({ tags, onChange }: { tags: string[]; onChange: (t: string[]) => void }) {
  const [input, setInput] = useState('')
  function add() {
    const t = input.trim()
    if (t && !tags.includes(t)) onChange([...tags, t])
    setInput('')
  }
  return (
    <div>
      <div className="flex flex-wrap gap-1 mb-2 min-h-[28px]">
        {tags.map(t => (
          <span key={t} className="flex items-center gap-1 bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">
            {t}
            <button onClick={() => onChange(tags.filter(x => x !== t))} className="hover:text-red-400">×</button>
          </span>
        ))}
        {tags.length === 0 && <span className="text-xs text-gray-600">Keine Tags</span>}
      </div>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="Tag hinzufügen (Enter)"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), add())}
        />
        <button onClick={add} className="text-xs bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded">+</button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Edit-Modal
// ---------------------------------------------------------------------------

const ASSET_TYPES = ['server', 'client', 'switch', 'router', 'firewall', 'printer', 'vm', 'access-point', 'other']
const EXPOSURES  = ['INTERN', 'DMZ', 'EXTERN']

const ZONE_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  EXTERN:  { bg: '#1f0808', border: '#dc2626', text: '#fca5a5' },
  DMZ:     { bg: '#1f1508', border: '#d97706', text: '#fcd34d' },
  INTERN:  { bg: '#0f1c3e', border: '#2563eb', text: '#93c5fd' },
  MGMT:    { bg: '#0c2419', border: '#059669', text: '#6ee7b7' },
}
function zoneColor(z: string) {
  return ZONE_COLORS[z] ?? { bg: '#1f2937', border: '#4b5563', text: '#d1d5db' }
}

function EditModal({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    hostname:       asset.hostname ?? '',
    ip_address:     asset.ip_address ?? '',
    fqdn:           asset.fqdn ?? '',
    mac_address:    asset.mac_address ?? '',
    asset_type:     asset.asset_type,
    os_name:        asset.os_name ?? '',
    os_version:     asset.os_version ?? '',
    exposure_level: asset.exposure_level,
    location:       (asset as any).location ?? '',
    tags:           asset.tags ?? [],
    network_zones:  (asset as any).network_zones ?? [],
    additional_ips: (asset as any).additional_ips ?? [],
    min_confidence: (asset as any).min_confidence ?? 0,
  })
  const [error, setError] = useState('')

  const update = useMutation({
    mutationFn: () => api.assets.update(asset.id, form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset', asset.id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      onClose()
    },
    onError: (e: Error) => setError(e.message),
  })

  const field = (label: string, key: keyof typeof form, type = 'text') => (
    <div>
      <label className="block text-xs text-gray-400 mb-1">{label}</label>
      <input
        type={type}
        className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
        value={form[key] as string}
        onChange={e => setForm({ ...form, [key]: e.target.value })}
      />
    </div>
  )

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="font-semibold text-lg">Asset bearbeiten</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><X size={18} /></button>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            {field('Hostname', 'hostname')}
            {field('IP-Adresse', 'ip_address')}
            {field('FQDN', 'fqdn')}
            {field('MAC-Adresse', 'mac_address')}
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-2">
              Weitere IP-Adressen
              <span className="text-gray-600 ml-2 font-normal">z.B. WAN-IP, Management-IP, zweites Interface</span>
            </label>
            <TagInput
              tags={form.additional_ips}
              onChange={ips => setForm({ ...form, additional_ips: ips })}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            {field('OS Name', 'os_name')}
            {field('OS Version', 'os_version')}
            {field('Standort', 'location')}

            <div>
              <label className="block text-xs text-gray-400 mb-1">Asset-Typ</label>
              <select
                className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
                value={form.asset_type}
                onChange={e => setForm({ ...form, asset_type: e.target.value })}
              >
                {ASSET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>

          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Exposure Level (höchste Risikostufe)</label>
            <select
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
              value={form.exposure_level}
              onChange={e => setForm({ ...form, exposure_level: e.target.value as any })}
            >
              {EXPOSURES.map(e => <option key={e} value={e}>{e}</option>)}
            </select>
          </div>

          <div className="col-span-2">
            <label className="block text-xs text-gray-400 mb-1">
              Netzwerk-Zonen
              <span className="text-gray-600 ml-2 font-normal">Namen der Netze (z.B. INTERN, DMZ, Heimnetz, Office-LAN)</span>
            </label>
            <TagInput
              tags={form.network_zones}
              onChange={zones => setForm({ ...form, network_zones: zones })}
            />
          </div>

          <div className="col-span-2">
            <label className="block text-xs text-gray-400 mb-2">Tags</label>
            <TagInput tags={form.tags} onChange={tags => setForm({ ...form, tags })} />
          </div>

          {/* Mindest-Konfidenz */}
          <div className="col-span-2">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-gray-400">
                Mindest-Konfidenz für automatische Updates
              </label>
              <span className="text-xs font-mono font-bold text-indigo-400">
                {form.min_confidence.toFixed(2)}
              </span>
            </div>
            <input
              type="range" min={0} max={1} step={0.05}
              value={form.min_confidence}
              onChange={e => setForm({ ...form, min_confidence: parseFloat(e.target.value) })}
              className="w-full accent-indigo-500"
            />
            <div className="flex justify-between text-xs text-gray-600 mt-1">
              <span>0.00 — alles</span>
              <span>0.80 — 2 Soft Keys</span>
              <span>0.95 — Stable Key</span>
              <span>1.00 — nur UUID</span>
            </div>
            <p className="text-xs text-gray-600 mt-1">
              {form.min_confidence === 0
                ? 'Alle automatischen Updates akzeptiert'
                : form.min_confidence <= 0.5
                ? 'Schwache Matches werden ignoriert'
                : form.min_confidence <= 0.85
                ? 'Nur 2+ Soft Keys oder Stable Keys werden akzeptiert'
                : form.min_confidence <= 0.99
                ? 'Nur Stable Keys (MAC, Serial, Chassis-ID) akzeptiert'
                : 'Nur UUID-Match — kein automatisches Update möglich'}
            </p>
          </div>

          {error && (
            <p className="text-sm text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>
          )}
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t border-gray-800">
          <button onClick={onClose} className="text-sm text-gray-400 hover:text-gray-200 px-4 py-2">
            Abbrechen
          </button>
          <button
            onClick={() => update.mutate()}
            disabled={update.isPending}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-sm px-4 py-2 rounded-lg"
          >
            <Check size={14} /> {update.isPending ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptseite
// ---------------------------------------------------------------------------

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [tab, setTab] = useState<'info' | 'history' | 'reports' | 'card'>('info')
  const [cardTemplate, setCardTemplate] = useState('full')
  const [cardPreview, setCardPreview] = useState('')
  const [cardLoading, setCardLoading] = useState(false)

  const { data: asset, isLoading } = useQuery({
    queryKey: ['asset', id],
    queryFn: () => api.assets.get(id!),
    enabled: !!id,
  })

  const { data: sbom = [] } = useQuery({
    queryKey: ['sbom', id],
    queryFn: () => api.sbom.get(id!),
    enabled: !!id,
  })

  const del = useMutation({
    mutationFn: () => api.assets.delete(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      navigate('/assets')
    },
  })

  if (isLoading) return <div className="text-gray-500 p-4">Laden…</div>
  if (!asset) return <div className="text-red-400 p-4">Asset nicht gefunden</div>

  return (
    <div className="max-w-4xl">
      {/* Back + Actions */}
      <div className="flex items-center justify-between mb-5">
        <button
          onClick={() => navigate('/assets')}
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
        >
          <ArrowLeft size={14} /> Zurück
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setEditing(true)}
            className="flex items-center gap-1.5 text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg border border-gray-700 transition-colors"
          >
            <Pencil size={13} /> Bearbeiten
          </button>
          {!confirmDelete ? (
            <button
              onClick={() => setConfirmDelete(true)}
              className="flex items-center gap-1.5 text-sm bg-gray-800 hover:bg-red-900 text-gray-400 hover:text-red-300 px-3 py-1.5 rounded-lg border border-gray-700 hover:border-red-800 transition-colors"
            >
              <Trash2 size={13} /> Löschen
            </button>
          ) : (
            <div className="flex items-center gap-2 bg-red-950 border border-red-800 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-300">Sicher?</span>
              <button
                onClick={() => del.mutate()}
                className="text-xs bg-red-600 hover:bg-red-500 text-white px-2 py-0.5 rounded"
              >
                Ja, löschen
              </button>
              <button onClick={() => setConfirmDelete(false)} className="text-xs text-gray-500 hover:text-gray-300">
                Abbrechen
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">{asset.hostname ?? asset.ip_address}</h1>
          <div className="flex items-center gap-3 mt-1">
            <p className="text-gray-500 text-sm">{asset.fqdn ?? asset.ip_address}</p>
            <LastSeen date={(asset as any).last_seen_at} />
          </div>
        </div>
        <Badge value={asset.exposure_level} />
      </div>

      {/* Info Grid */}
      <div className="grid grid-cols-2 gap-3 mb-6">
        {[
          ['Typ',  asset.asset_type],
          ['OS',   `${asset.os_name ?? '—'} ${asset.os_version ?? ''}`],
          ['IP',   [asset.ip_address, ...((asset as any).additional_ips ?? [])].filter(Boolean).join(', ') || '—'],
          ['MAC',  asset.mac_address ?? '—'],
        ].map(([label, value]) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <div className="text-xs text-gray-500 mb-1">{label}</div>
            <div className="text-sm font-medium">{value}</div>
          </div>
        ))}
      </div>

      {/* Network Zones */}
      {(asset as any).network_zones?.length > 0 && (
        <div className="mb-4">
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Netzwerk-Zonen</div>
          <div className="flex gap-2 flex-wrap">
            {(asset as any).network_zones.map((zone: string) => (
              <span key={zone} className="text-xs font-medium px-2.5 py-1 rounded-full border"
                style={{ background: zoneColor(zone).bg, color: zoneColor(zone).text, borderColor: zoneColor(zone).border }}>
                {zone}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Tab-Navigation */}
      <div className="flex gap-1 mb-6 border-b border-gray-800 pb-0">
        {[
          { id: 'info', label: 'Details' },
          { id: 'history', label: 'Verlauf', icon: History },
          { id: 'reports', label: 'Reports', icon: FileText },
          { id: 'card', label: 'Karteikarte', icon: CreditCard },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id as any)}
            className={`flex items-center gap-1.5 px-4 py-2 text-sm border-b-2 transition-colors ${
              tab === id
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {Icon && <Icon size={13} />}{label}
          </button>
        ))}
      </div>

      {tab === 'history' && (
        <section className="mb-6">
          <SnapshotTimeline assetId={id!} />
        </section>
      )}

      {tab === 'reports' && (
        <section className="mb-6">
          <ReportViewer assetId={id!} />
        </section>
      )}

      {tab === 'card' && (
        <section className="mb-6">
          <div className="space-y-3">
            {/* Template + Download */}
            <div className="flex items-center gap-3">
              <select
                className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
                value={cardTemplate}
                onChange={e => { setCardTemplate(e.target.value); setCardPreview('') }}
              >
                {[
                  { id: 'full', label: 'Vollständig' },
                  { id: 'security', label: 'Security-fokussiert' },
                  { id: 'inventory', label: 'Inventar' },
                  { id: 'network', label: 'Netzwerk' },
                  { id: 'minimal', label: 'Minimal' },
                ].map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
              <button
                onClick={async () => {
                  setCardLoading(true)
                  try {
                    const res = await fetch(`/api/v1/cards/assets/${id}`, {
                      method: 'POST',
                      headers: { Authorization: `Bearer ${localStorage.getItem('token')}`, 'Content-Type': 'application/json' },
                      body: JSON.stringify({ template_id: cardTemplate, format: 'markdown' }),
                    })
                    setCardPreview(await res.text())
                  } finally { setCardLoading(false) }
                }}
                disabled={cardLoading}
                className="flex items-center gap-1.5 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-gray-300 px-3 py-1.5 rounded"
              >
                <CreditCard size={13} /> {cardLoading ? 'Lade…' : 'Vorschau'}
              </button>
              {cardPreview && (
                <a
                  href={`/api/v1/cards/assets/${id}`}
                  onClick={async e => {
                    e.preventDefault()
                    const res = await fetch(`/api/v1/cards/assets/${id}`, {
                      method: 'POST',
                      headers: { Authorization: `Bearer ${localStorage.getItem('token')}`, 'Content-Type': 'application/json' },
                      body: JSON.stringify({ template_id: cardTemplate, format: 'markdown' }),
                    })
                    const blob = await res.blob()
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a')
                    a.href = url; a.download = `${asset.hostname || id}_card.md`; a.click()
                    URL.revokeObjectURL(url)
                  }}
                  className="flex items-center gap-1.5 text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded"
                >
                  ↓ Download
                </a>
              )}
            </div>

            {/* Vorschau */}
            {cardPreview && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 max-h-[600px] overflow-y-auto">
                <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">{cardPreview}</pre>
              </div>
            )}
            {!cardPreview && !cardLoading && (
              <div className="text-gray-600 text-sm py-4">
                Template auswählen → „Vorschau" klicken
              </div>
            )}
          </div>
        </section>
      )}

      {tab === 'info' && <>

      {/* Tags + Konfidenz-Badge */}
      <div className="flex gap-2 mb-6 flex-wrap items-center">
        {(asset.tags ?? []).map(tag => (
          <span key={tag} className="text-xs bg-gray-800 text-gray-400 px-2 py-1 rounded">{tag}</span>
        ))}
        {(!asset.tags || asset.tags.length === 0) && (
          <span className="text-xs text-gray-600">Keine Tags — über „Bearbeiten" hinzufügen</span>
        )}
        {(asset as any).min_confidence > 0 && (
          <span className="ml-auto text-xs bg-indigo-950 border border-indigo-800 text-indigo-400 px-2 py-1 rounded flex items-center gap-1">
            🔒 Min. Konfidenz: {((asset as any).min_confidence).toFixed(2)}
          </span>
        )}
      </div>

      {/* Ports */}
      {asset.open_ports && asset.open_ports.length > 0 && (
        <section className="mb-6">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Network size={14} /> Offene Ports
          </h2>
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                  <th className="text-left px-4 py-2">Port</th>
                  <th className="text-left px-4 py-2">Protokoll</th>
                  <th className="text-left px-4 py-2">Erreichbar von</th>
                </tr>
              </thead>
              <tbody>
                {asset.open_ports.map(p => (
                  <tr key={p.port} className="border-b border-gray-800">
                    <td className="px-4 py-2 font-mono text-indigo-400">{p.port}</td>
                    <td className="px-4 py-2 text-gray-400">{p.proto}</td>
                    <td className="px-4 py-2">
                      {p.reachable_from.map(r => (
                        <span key={r} className={`text-xs mr-1 px-2 py-0.5 rounded ${
                          r === 'internet' ? 'bg-red-900 text-red-300' : 'bg-gray-800 text-gray-400'
                        }`}>{r}</span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* SBOM */}
      <section>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
          <Package size={14} /> SBOM ({sbom.length} Pakete)
        </h2>
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                <th className="text-left px-4 py-2">Paket</th>
                <th className="text-left px-4 py-2">Version</th>
                <th className="text-left px-4 py-2">Typ</th>
                <th className="text-left px-4 py-2">Quelle</th>
              </tr>
            </thead>
            <tbody>
              {sbom.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-600">Kein SBOM vorhanden</td></tr>
              )}
              {sbom.map(e => (
                <tr key={e.id} className="border-b border-gray-800">
                  <td className="px-4 py-2 font-medium">{e.pkg_name}</td>
                  <td className="px-4 py-2 font-mono text-gray-400">{e.pkg_version}</td>
                  <td className="px-4 py-2 text-gray-500">{e.pkg_type ?? '—'}</td>
                  <td className="px-4 py-2 text-gray-500">{e.source ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      </>}

      {/* Edit Modal */}
      {editing && <EditModal asset={asset} onClose={() => setEditing(false)} />}
    </div>
  )
}
