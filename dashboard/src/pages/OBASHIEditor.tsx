/**
 * OBASHI-Editor
 *
 * Ermöglicht das freie Anlegen von Prozessen und Anwendungen.
 * Anwendungen werden mit Assets verknüpft → S/H/I-Layer automatisch.
 *
 * Aufbau:
 *   Linke Spalte: Baum O → B → A
 *   Rechte Spalte: Editor für das ausgewählte Element + Asset-Verknüpfung
 */

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  ChevronRight, ChevronDown, Plus, Trash2,
  User, Workflow, Settings2, Server, Network, Package,
  Check, X, Link,
} from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(path, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json', ...opts?.headers },
  })
  if (!res.ok) throw new Error(await res.text())
  if (res.status === 204) return undefined
  return res.json()
}

const api = {
  owners:   { list: () => apiFetch('/api/v1/owners'), create: (b: any) => apiFetch('/api/v1/owners', { method: 'POST', body: JSON.stringify(b) }), delete: (id: string) => apiFetch(`/api/v1/owners/${id}`, { method: 'DELETE' }) },
  procs:    { list: () => apiFetch('/api/v1/processes'), create: (b: any) => apiFetch('/api/v1/processes', { method: 'POST', body: JSON.stringify(b) }), update: (id: string, b: any) => apiFetch(`/api/v1/processes/${id}`, { method: 'PUT', body: JSON.stringify(b) }), delete: (id: string) => apiFetch(`/api/v1/processes/${id}`, { method: 'DELETE' }) },
  apps:     { list: (pid?: string) => apiFetch(`/api/v1/applications${pid ? '?process_id='+pid : ''}`), create: (b: any) => apiFetch('/api/v1/applications', { method: 'POST', body: JSON.stringify(b) }), update: (id: string, b: any) => apiFetch(`/api/v1/applications/${id}`, { method: 'PUT', body: JSON.stringify(b) }), delete: (id: string) => apiFetch(`/api/v1/applications/${id}`, { method: 'DELETE' }) },
  assets:   { list: () => apiFetch('/api/v1/assets?limit=200') },
  sbom:     { get: (id: string) => apiFetch(`/api/v1/sbom/assets/${id}/sbom`) },
}

const APP_TYPES = ['web', 'api', 'batch', 'integration', 'service', 'desktop', 'mobile', 'other']
const TYPE_ICONS: Record<string, string> = { web:'🌐', api:'⚡', batch:'⚙', integration:'🔗', service:'🔧', desktop:'🖥', mobile:'📱', other:'📦' }

// ---------------------------------------------------------------------------
// Baum-Komponenten
// ---------------------------------------------------------------------------

function TreeSection({ icon: Icon, label, color, children, onAdd }: any) {
  return (
    <div>
      <div className="flex items-center gap-2 px-2 py-1.5 text-xs font-semibold uppercase tracking-wider text-gray-500">
        <Icon size={12} className={color} />
        {label}
        {onAdd && (
          <button onClick={onAdd} className="ml-auto text-gray-600 hover:text-indigo-400 transition-colors">
            <Plus size={12} />
          </button>
        )}
      </div>
      {children}
    </div>
  )
}

function TreeItem({ label, sublabel, selected, onClick, onDelete, indent = 0, icon }: any) {
  return (
    <div
      onClick={onClick}
      className={`flex items-center gap-2 px-2 py-1.5 rounded-md cursor-pointer transition-colors text-sm group ${
        selected ? 'bg-indigo-600 text-white' : 'hover:bg-gray-800 text-gray-300'
      }`}
      style={{ paddingLeft: `${(indent * 12) + 8}px` }}
    >
      {icon && <span className="text-xs shrink-0">{icon}</span>}
      <div className="flex-1 min-w-0">
        <div className="truncate text-xs font-medium">{label}</div>
        {sublabel && <div className={`truncate text-xs ${selected ? 'text-indigo-200' : 'text-gray-500'}`}>{sublabel}</div>}
      </div>
      {onDelete && (
        <button
          onClick={e => { e.stopPropagation(); onDelete() }}
          className={`opacity-0 group-hover:opacity-100 transition-all ${selected ? 'text-indigo-200 hover:text-white' : 'text-gray-600 hover:text-red-400'}`}
        >
          <Trash2 size={11} />
        </button>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Editor-Panel: Prozess
// ---------------------------------------------------------------------------

function ProcessEditor({ proc, owners, onSaved }: any) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name: proc?.name || '',
    description: proc?.description || '',
    criticality: proc?.criticality || 3,
    sla_rto_hours: proc?.sla_rto_hours || '',
    sla_rpo_hours: proc?.sla_rpo_hours || '',
    owner_id: proc?.owner_id || '',
  })

  const save = useMutation({
    mutationFn: () => proc?.id
      ? api.procs.update(proc.id, { ...form, sla_rto_hours: form.sla_rto_hours || null, sla_rpo_hours: form.sla_rpo_hours || null, owner_id: form.owner_id || null })
      : api.procs.create({ ...form, sla_rto_hours: form.sla_rto_hours || null, sla_rpo_hours: form.sla_rpo_hours || null, owner_id: form.owner_id || null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['obashi-procs'] }); onSaved?.() },
  })

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold flex items-center gap-2 text-blue-400">
        <Workflow size={14} /> {proc?.id ? 'Prozess bearbeiten' : 'Neuer Prozess'}
      </h3>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-blue-500"
        placeholder="Name des Prozesses" value={form.name} onChange={e => setForm({...form, name: e.target.value})} />
      <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none resize-none"
        placeholder="Beschreibung (optional)" rows={2} value={form.description} onChange={e => setForm({...form, description: e.target.value})} />
      <div className="grid grid-cols-3 gap-2">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Kritikalität</label>
          <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.criticality} onChange={e => setForm({...form, criticality: +e.target.value})}>
            {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}/5</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">RTO (Std.)</label>
          <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="4" value={form.sla_rto_hours} onChange={e => setForm({...form, sla_rto_hours: e.target.value})} />
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">RPO (Std.)</label>
          <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="1" value={form.sla_rpo_hours} onChange={e => setForm({...form, sla_rpo_hours: e.target.value})} />
        </div>
      </div>
      <div>
        <label className="block text-xs text-gray-500 mb-1">Owner</label>
        <select className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
          value={form.owner_id} onChange={e => setForm({...form, owner_id: e.target.value})}>
          <option value="">— kein Owner —</option>
          {owners.map((o: any) => <option key={o.id} value={o.id}>{o.name}{o.team ? ` (${o.team})` : ''}</option>)}
        </select>
      </div>
      <button onClick={() => save.mutate()} disabled={!form.name || save.isPending}
        className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm py-2 rounded-lg">
        <Check size={14} /> {save.isPending ? 'Speichern…' : 'Speichern'}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Editor-Panel: Anwendung + Asset-Verknüpfung
// ---------------------------------------------------------------------------

function AppEditor({ app, processId, assets, onSaved }: any) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name:        app?.name || '',
    app_type:    app?.app_type || 'web',
    version:     app?.version || '',
    url:         app?.url || '',
    description: app?.description || '',
    owner_id:    app?.owner_id || '',
    criticality: app?.criticality || '',
    asset_ids:   (app?.asset_ids || []) as string[],
    process_id:  app?.process_id || processId || '',
  })
  const [assetSearch, setAssetSearch] = useState('')
  const [showSbom, setShowSbom] = useState<string | null>(null)
  const { data: sbom = [] } = useQuery({ queryKey: ['sbom', showSbom], queryFn: () => api.sbom.get(showSbom!), enabled: !!showSbom })

  const save = useMutation({
    mutationFn: () => app?.id
      ? api.apps.update(app.id, { ...form, version: form.version || null, url: form.url || null, description: form.description || null, owner_id: form.owner_id || null, criticality: form.criticality ? +form.criticality : null })
      : api.apps.create({ ...form, version: form.version || null, url: form.url || null, description: form.description || null, owner_id: form.owner_id || null, criticality: form.criticality ? +form.criticality : null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['obashi-apps'] }); onSaved?.() },
  })

  const toggleAsset = (id: string) => {
    setForm(f => ({
      ...f,
      asset_ids: f.asset_ids.includes(id) ? f.asset_ids.filter(a => a !== id) : [...f.asset_ids, id],
    }))
  }

  const filteredAssets = assets.filter((a: any) =>
    !assetSearch || [a.hostname, a.ip_address, a.asset_type].some(v => v?.toLowerCase().includes(assetSearch.toLowerCase()))
  )

  const linkedAssets = assets.filter((a: any) => form.asset_ids.includes(a.id))

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold flex items-center gap-2 text-green-400">
        <Settings2 size={14} /> {app?.id ? 'Anwendung bearbeiten' : 'Neue Anwendung'}
        {form.process_id && <span className="text-xs text-gray-500 font-normal ml-1">(A-Layer)</span>}
      </h3>

      <div className="grid grid-cols-2 gap-2">
        <div className="col-span-2">
          <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-green-500"
            placeholder="Name (z.B. Webshop, CRM, ERP)" value={form.name} onChange={e => setForm({...form, name: e.target.value})} />
        </div>
        <div>
          <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={form.app_type} onChange={e => setForm({...form, app_type: e.target.value})}>
            {APP_TYPES.map(t => <option key={t} value={t}>{TYPE_ICONS[t]} {t}</option>)}
          </select>
        </div>
        <div>
          <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="Version (optional)" value={form.version} onChange={e => setForm({...form, version: e.target.value})} />
        </div>
        <div className="col-span-2">
          <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            placeholder="URL (optional)" value={form.url} onChange={e => setForm({...form, url: e.target.value})} />
        </div>
      </div>

      {/* Asset-Verknüpfung (S/H/I-Layer) */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-semibold text-gray-400 flex items-center gap-1">
            <Link size={11} /> Verknüpfte Assets <span className="text-gray-600 font-normal">(S/H/I-Layer)</span>
          </label>
          <span className="text-xs text-gray-600">{form.asset_ids.length} ausgewählt</span>
        </div>

        {/* Bereits verknüpfte Assets als Chips */}
        {linkedAssets.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-2">
            {linkedAssets.map((a: any) => (
              <button key={a.id} onClick={() => toggleAsset(a.id)}
                className="flex items-center gap-1 text-xs bg-green-900/50 text-green-400 border border-green-700 px-2 py-0.5 rounded hover:bg-red-900/50 hover:text-red-400 hover:border-red-700 transition-colors">
                <Server size={9} /> {a.hostname || a.ip_address}
                <X size={9} />
              </button>
            ))}
          </div>
        )}

        {/* Asset-Suche + Liste */}
        <input className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none mb-1"
          placeholder="Asset suchen (Hostname, IP, Typ)..."
          value={assetSearch} onChange={e => setAssetSearch(e.target.value)} />
        <div className="max-h-36 overflow-y-auto border border-gray-700 rounded divide-y divide-gray-800">
          {filteredAssets.slice(0, 30).map((a: any) => {
            const linked = form.asset_ids.includes(a.id)
            return (
              <button key={a.id} onClick={() => toggleAsset(a.id)}
                className={`w-full flex items-center gap-2 px-2 py-1 text-left text-xs transition-colors ${
                  linked ? 'bg-green-900/30 text-green-300' : 'hover:bg-gray-800 text-gray-400'
                }`}>
                {linked ? <Check size={10} className="text-green-400 shrink-0" /> : <div className="w-2.5 shrink-0" />}
                <span className="font-medium truncate">{a.hostname || '—'}</span>
                <span className="text-gray-600 shrink-0">{a.ip_address}</span>
                <span className="text-gray-700 shrink-0 text-xs">{a.asset_type}</span>
                {linked && (
                  <button onClick={e => { e.stopPropagation(); setShowSbom(showSbom === a.id ? null : a.id) }}
                    className="ml-auto text-gray-600 hover:text-yellow-400" title="SBOM anzeigen">
                    <Package size={10} />
                  </button>
                )}
              </button>
            )
          })}
          {filteredAssets.length === 0 && (
            <div className="px-3 py-3 text-xs text-gray-600 text-center">Keine Assets gefunden</div>
          )}
        </div>

        {/* SBOM-Preview */}
        {showSbom && sbom.length > 0 && (
          <div className="mt-1 bg-gray-900 border border-yellow-800/50 rounded p-2">
            <div className="text-xs text-yellow-600 mb-1 font-medium">SBOM ({sbom.length} Pakete) → S-Layer</div>
            <div className="flex flex-wrap gap-1 max-h-16 overflow-y-auto">
              {sbom.slice(0, 20).map((e: any) => (
                <span key={e.id} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded font-mono">
                  {e.pkg_name} {e.pkg_version}
                </span>
              ))}
              {sbom.length > 20 && <span className="text-xs text-gray-600">+{sbom.length - 20}</span>}
            </div>
          </div>
        )}
      </div>

      <button onClick={() => save.mutate()} disabled={!form.name || !form.process_id || save.isPending}
        className="w-full flex items-center justify-center gap-2 bg-green-700 hover:bg-green-600 disabled:opacity-40 text-white text-sm py-2 rounded-lg">
        <Check size={14} /> {save.isPending ? 'Speichern…' : 'Speichern'}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Owner-Editor (Inline)
// ---------------------------------------------------------------------------

function OwnerEditor({ onSaved }: any) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', email: '', team: '', department: '', role: '' })
  const save = useMutation({
    mutationFn: () => api.owners.create({ ...form, email: form.email||null, team: form.team||null, department: form.department||null, role: form.role||null }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['obashi-owners'] }); setForm({ name:'', email:'', team:'', department:'', role:'' }); onSaved?.() },
  })
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold flex items-center gap-2 text-purple-400"><User size={14} /> Neuer Owner</h3>
      <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
        placeholder="Name *" value={form.name} onChange={e => setForm({...form, name: e.target.value})} />
      <div className="grid grid-cols-2 gap-2">
        <input className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
          placeholder="Team" value={form.team} onChange={e => setForm({...form, team: e.target.value})} />
        <input className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
          placeholder="Abteilung" value={form.department} onChange={e => setForm({...form, department: e.target.value})} />
      </div>
      <button onClick={() => save.mutate()} disabled={!form.name}
        className="w-full bg-purple-700 hover:bg-purple-600 disabled:opacity-40 text-white text-sm py-1.5 rounded-lg">
        Owner anlegen
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptseite
// ---------------------------------------------------------------------------

type Selection = { type: 'proc' | 'app' | 'new-proc' | 'new-app' | 'new-owner'; id?: string; context?: string }

export default function OBASHIEditor() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [sel, setSel] = useState<Selection | null>(null)
  const [expandedProcs, setExpandedProcs] = useState<Set<string>>(new Set())

  const { data: owners = [] } = useQuery({ queryKey: ['obashi-owners'], queryFn: api.owners.list })
  const { data: procs = [] }  = useQuery({ queryKey: ['obashi-procs'],  queryFn: api.procs.list })
  const { data: apps = [] }   = useQuery({ queryKey: ['obashi-apps'],   queryFn: () => api.apps.list() })
  const { data: assets = [] } = useQuery({ queryKey: ['assets-all'],    queryFn: api.assets.list })

  const delProc = useMutation({ mutationFn: (id: string) => api.procs.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['obashi-procs'] }) })
  const delApp  = useMutation({ mutationFn: (id: string) => api.apps.delete(id),  onSuccess: () => qc.invalidateQueries({ queryKey: ['obashi-apps'] }) })
  const delOwner = useMutation({ mutationFn: (id: string) => api.owners.delete(id), onSuccess: () => qc.invalidateQueries({ queryKey: ['obashi-owners'] }) })

  const toggleProc = (id: string) => setExpandedProcs(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })

  const selProc = procs.find((p: any) => p.id === sel?.id)
  const selApp  = apps.find((a: any) => a.id === sel?.id)

  const appsForProc = (pid: string) => (apps as any[]).filter((a: any) => a.process_id === pid)

  return (
    <div className="max-w-6xl">
      <div className="mb-5">
        <h1 className="text-2xl font-bold">BASIS Editor</h1>
        <p className="text-sm text-gray-500 mt-1">
          BASIS (Business · Application · Service · Infrastructure · Systems) — Prozesse und Anwendungen anlegen, Assets verknüpfen
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4 h-[calc(100vh-200px)] min-h-[600px]">
        {/* ── Linke Spalte: Baum ─────────────────────────────────────── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-y-auto p-2 space-y-1">

          {/* O – Owners */}
          <TreeSection icon={User} label="O – Owners" color="text-purple-400"
            onAdd={() => setSel({ type: 'new-owner' })}>
            {owners.map((o: any) => (
              <TreeItem key={o.id} label={o.name} sublabel={o.team}
                selected={sel?.id === o.id}
                onClick={() => setSel({ type: 'proc', id: o.id })}
                onDelete={() => delOwner.mutate(o.id)} indent={1} />
            ))}
          </TreeSection>

          <div className="border-t border-gray-800 my-1" />

          {/* B – Prozesse */}
          <TreeSection icon={Workflow} label="B – Business-Prozesse" color="text-blue-400"
            onAdd={() => setSel({ type: 'new-proc' })}>
            {procs.map((p: any) => {
              const expanded = expandedProcs.has(p.id)
              const pApps = appsForProc(p.id)
              return (
                <div key={p.id}>
                  <div className={`flex items-center gap-1 px-2 py-1.5 rounded-md cursor-pointer group text-xs transition-colors ${
                    sel?.id === p.id && sel?.type === 'proc' ? 'bg-blue-600 text-white' : 'hover:bg-gray-800 text-gray-300'
                  }`}>
                    <button onClick={() => toggleProc(p.id)} className="shrink-0 text-gray-500">
                      {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    </button>
                    <div className="flex-1 min-w-0" onClick={() => setSel({ type: 'proc', id: p.id })}>
                      <div className="truncate font-medium">{p.name}</div>
                      <div className="text-gray-600 text-xs">Kritikalität {p.criticality}/5 · {pApps.length} Apps</div>
                    </div>
                    <button onClick={() => setSel({ type: 'new-app', context: p.id })}
                      className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-green-400 shrink-0" title="Neue App">
                      <Plus size={11} />
                    </button>
                    <button onClick={() => delProc.mutate(p.id)}
                      className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-red-400 shrink-0">
                      <Trash2 size={11} />
                    </button>
                  </div>

                  {/* A – Anwendungen */}
                  {expanded && pApps.map((a: any) => (
                    <TreeItem key={a.id}
                      label={`${TYPE_ICONS[a.app_type] || '📦'} ${a.name}`}
                      sublabel={`${a.app_type}${a.version ? ' · v'+a.version : ''}${a.asset_ids?.length ? ' · '+a.asset_ids.length+' Assets' : ''}`}
                      selected={sel?.id === a.id}
                      onClick={() => setSel({ type: 'app', id: a.id })}
                      onDelete={() => delApp.mutate(a.id)}
                      indent={2} />
                  ))}
                  {expanded && pApps.length === 0 && (
                    <div className="text-xs text-gray-700 py-1" style={{ paddingLeft: '24px' }}>
                      Keine Anwendungen — + klicken
                    </div>
                  )}
                </div>
              )
            })}
          </TreeSection>
        </div>

        {/* ── Mittlere Spalte: Editor ───────────────────────────────── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 overflow-y-auto">
          {!sel && (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 text-sm text-center">
              <Workflow size={32} className="mb-3 opacity-30" />
              <p>Element auswählen oder</p>
              <p>+ zum Anlegen klicken</p>
            </div>
          )}

          {sel?.type === 'new-owner' && (
            <OwnerEditor onSaved={() => setSel(null)} />
          )}

          {(sel?.type === 'new-proc') && (
            <ProcessEditor owners={owners} onSaved={() => setSel(null)} />
          )}

          {sel?.type === 'proc' && selProc && (
            <ProcessEditor proc={selProc} owners={owners} onSaved={() => {}} />
          )}

          {sel?.type === 'new-app' && (
            <AppEditor processId={sel?.context} assets={assets} onSaved={() => setSel(null)} />
          )}

          {sel?.type === 'app' && selApp && (
            <AppEditor app={selApp} processId={selApp.process_id} owners={owners} assets={assets} onSaved={() => {}} />
          )}
        </div>

        {/* ── Rechte Spalte: Layer-Vorschau ────────────────────────── */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 overflow-y-auto">
          {sel?.type === 'app' && selApp ? (
            <AppLayerPreview app={selApp} assets={assets} />
          ) : sel?.type === 'proc' && selProc ? (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-gray-400">BASIS-Ansicht</h3>
              <button
                onClick={() => navigate('/processes')}
                className="w-full text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 py-2 rounded-lg border border-gray-700"
              >
                Vollständige BASIS-Ansicht öffnen
              </button>
              <div className="text-xs text-gray-600 space-y-1">
                {appsForProc(selProc!.id).map((a: any) => (
                  <div key={a.id} className="flex items-center gap-2">
                    <span>{TYPE_ICONS[a.app_type] || '📦'}</span>
                    <span className="text-gray-400">{a.name}</span>
                    <span className="text-gray-600">→ {a.asset_ids?.length || 0} Assets</span>
                  </div>
                ))}
                {appsForProc(selProc!.id).length === 0 && (
                  <p className="text-gray-700">Noch keine Anwendungen</p>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-700 text-xs text-center">
              <Network size={24} className="mb-2 opacity-30" />
              <p>Layer-Vorschau erscheint</p>
              <p>wenn eine Anwendung ausgewählt ist</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Layer-Vorschau für eine Anwendung
// ---------------------------------------------------------------------------

function AppLayerPreview({ app, assets }: { app: any; assets: any[] }) {
  const linkedAssets = assets.filter((a: any) => (app.asset_ids || []).includes(a.id))
  const { data: sbomMap } = useQuery({
    queryKey: ['sbom-multi', app.id],
    queryFn: async () => {
      const map: Record<string, any[]> = {}
      for (const a of linkedAssets) {
        const t = localStorage.getItem('token') ?? ''
        const r = await fetch(`/api/v1/sbom/assets/${a.id}/sbom`, { headers: { Authorization: `Bearer ${t}` }})
        if (r.ok) map[a.id] = await r.json()
      }
      return map
    },
    enabled: linkedAssets.length > 0,
  })

  const LAYERS = [
    { id: 'A', label: 'Application', color: '#059669', items: [`${TYPE_ICONS[app.app_type]||'📦'} ${app.name}${app.version ? ' v'+app.version : ''}`] },
    { id: 'S', label: 'System', color: '#d97706', items: linkedAssets.flatMap(a => [
      a.os_name ? `${a.os_name} ${a.os_version||''}`.trim() : null,
      ...((sbomMap?.[a.id] || []).filter((e: any) => ['application','library'].includes(e.pkg_type||'')).slice(0,5).map((e: any) => `${e.pkg_name} ${e.pkg_version}`)),
    ].filter(Boolean)) },
    { id: 'H', label: 'Hardware', color: '#ea580c', items: linkedAssets.map(a => `${a.hostname||a.ip_address} (${a.asset_type})`) },
    { id: 'I', label: 'Infrastructure', color: '#dc2626', items: linkedAssets.flatMap(a => [
      `${a.exposure_level}`,
      ...(a.open_ports||[]).slice(0,3).map((p: any) => `Port ${p.port}/${p.proto}`),
    ]) },
  ]

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-gray-400">Layer-Vorschau</h3>
      <div className="text-xs text-gray-600">{app.name} → {linkedAssets.length} Assets verknüpft</div>
      {LAYERS.map(layer => (
        <div key={layer.id} className="rounded-lg border p-2.5"
          style={{ borderColor: layer.color + '40', background: layer.color + '10' }}>
          <div className="text-xs font-bold mb-1.5" style={{ color: layer.color }}>
            {layer.id} – {layer.label}
          </div>
          {layer.items.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {[...new Set(layer.items)].slice(0, 10).map((item, i) => (
                <span key={i} className="text-xs bg-gray-900/80 text-gray-400 px-2 py-0.5 rounded font-mono">
                  {item as string}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-xs text-gray-700">—</span>
          )}
        </div>
      ))}
    </div>
  )
}
