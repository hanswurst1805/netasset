import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type Owner, type AppEntity } from '../api/client'
import Badge from '../components/Badge'
import BasisDiagram from '../components/BasisDiagram'
import { ChevronDown, ChevronUp, Layers, BarChart2, Plus, Trash2, User, Settings2, Workflow } from 'lucide-react'

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

function CriticalityBar({ value }: { value: number }) {
  const colors = ['', 'bg-green-500', 'bg-green-400', 'bg-yellow-400', 'bg-orange-400', 'bg-red-500']
  return (
    <div className="flex gap-0.5">
      {[1,2,3,4,5].map(i => (
        <div key={i} className={`h-2 w-4 rounded-sm ${i <= value ? colors[value] : 'bg-gray-700'}`} />
      ))}
    </div>
  )
}

async function fetchObashi(id: string) {
  const token = localStorage.getItem('token')
  const res = await fetch(`/api/v1/processes/${id}/basis`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!res.ok) throw new Error('BASIS-Daten konnten nicht geladen werden')
  return res.json()
}

// ---------------------------------------------------------------------------
// Owner-Picker
// ---------------------------------------------------------------------------

function OwnerPicker({ value, onChange }: { value: string | null; onChange: (id: string | null) => void }) {
  const { data: owners = [] } = useQuery({ queryKey: ['owners'], queryFn: api.owners.list })
  return (
    <select
      className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-300 focus:outline-none"
      value={value ?? ''}
      onChange={e => onChange(e.target.value || null)}
    >
      <option value="">— kein Owner —</option>
      {owners.map((o: Owner) => (
        <option key={o.id} value={o.id}>{o.name}{o.team ? ` (${o.team})` : ''}</option>
      ))}
    </select>
  )
}

// ---------------------------------------------------------------------------
// Application-Verwaltung
// ---------------------------------------------------------------------------

const APP_TYPES = ['web', 'api', 'batch', 'integration', 'service', 'desktop', 'mobile', 'other']
const TYPE_ICONS: Record<string, string> = {
  web: '🌐', api: '⚡', batch: '⚙', integration: '🔗', service: '🔧', desktop: '🖥', mobile: '📱', other: '📦'
}

function ApplicationManager({ processId, owners }: { processId: string; owners: Owner[] }) {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)
  const [form, setForm] = useState({
    name: '', app_type: 'web', version: '', url: '', description: '',
    owner_id: '', criticality: '', process_id: processId
  })

  const { data: apps = [] } = useQuery({
    queryKey: ['apps', processId],
    queryFn: () => api.applications.list(processId),
  })

  const create = useMutation({
    mutationFn: () => api.applications.create({
      ...form,
      owner_id: form.owner_id || null,
      criticality: form.criticality ? Number(form.criticality) : null,
      version: form.version || null,
      url: form.url || null,
      description: form.description || null,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['apps', processId] })
      qc.invalidateQueries({ queryKey: ['basis', processId] })
      setShowNew(false)
      setForm({ name: '', app_type: 'web', version: '', url: '', description: '', owner_id: '', criticality: '', process_id: processId })
    },
  })

  const del = useMutation({
    mutationFn: (id: string) => api.applications.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['apps', processId] })
      qc.invalidateQueries({ queryKey: ['basis', processId] })
    },
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 uppercase tracking-wider">
          A – Fachanwendungen ({apps.length})
        </span>
        <button
          onClick={() => setShowNew(!showNew)}
          className="flex items-center gap-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-2 py-1 rounded"
        >
          <Plus size={11} /> Neue Fachanwendung
        </button>
      </div>

      {/* Neue App Form */}
      {showNew && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 mb-3 space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <input
              className="col-span-2 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
              placeholder="Name der Fachanwendung (z.B. Webshop, CRM)"
              value={form.name}
              onChange={e => setForm({ ...form, name: e.target.value })}
            />
            <select
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              value={form.app_type}
              onChange={e => setForm({ ...form, app_type: e.target.value })}
            >
              {APP_TYPES.map(t => (
                <option key={t} value={t}>{TYPE_ICONS[t]} {t}</option>
              ))}
            </select>
            <input
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              placeholder="Version (optional)"
              value={form.version}
              onChange={e => setForm({ ...form, version: e.target.value })}
            />
            <input
              className="col-span-2 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              placeholder="URL (optional)"
              value={form.url}
              onChange={e => setForm({ ...form, url: e.target.value })}
            />
            <select
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              value={form.owner_id}
              onChange={e => setForm({ ...form, owner_id: e.target.value })}
            >
              <option value="">— App-Owner (optional) —</option>
              {owners.map(o => (
                <option key={o.id} value={o.id}>{o.name}{o.team ? ` (${o.team})` : ''}</option>
              ))}
            </select>
            <select
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              value={form.criticality}
              onChange={e => setForm({ ...form, criticality: e.target.value })}
            >
              <option value="">— Kritikalität —</option>
              {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}/5</option>)}
            </select>
          </div>
          <textarea
            className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none resize-none"
            rows={2}
            placeholder="Beschreibung (optional)"
            value={form.description}
            onChange={e => setForm({ ...form, description: e.target.value })}
          />
          <div className="flex gap-2 justify-end">
            <button onClick={() => setShowNew(false)} className="text-xs text-gray-500 hover:text-gray-300 px-3 py-1">Abbrechen</button>
            <button
              onClick={() => create.mutate()}
              disabled={!form.name}
              className="text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded"
            >
              Anlegen
            </button>
          </div>
        </div>
      )}

      {/* App-Liste */}
      <div className="space-y-1.5">
        {apps.map((app: AppEntity) => (
          <div key={app.id} className="flex items-center gap-3 bg-gray-800 rounded-lg px-3 py-2">
            <span className="text-base">{TYPE_ICONS[app.app_type || 'other'] || '📦'}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium truncate">{app.name}</div>
              <div className="text-xs text-gray-500 flex gap-2">
                <span>{app.app_type}</span>
                {app.version && <span>v{app.version}</span>}
                {app.criticality && <span>Krit. {app.criticality}/5</span>}
              </div>
            </div>
            <button
              onClick={() => del.mutate(app.id)}
              className="text-gray-600 hover:text-red-400 transition-colors shrink-0"
            >
              <Trash2 size={13} />
            </button>
          </div>
        ))}
        {apps.length === 0 && !showNew && (
          <p className="text-xs text-gray-600 py-2 text-center">
            Noch keine Fachanwendungen — „Neue Fachanwendung" anlegen
          </p>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Owner-Verwaltung Modal
// ---------------------------------------------------------------------------

function OwnerManagement({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { data: owners = [] } = useQuery({ queryKey: ['owners'], queryFn: api.owners.list })
  const [form, setForm] = useState({ name: '', email: '', team: '', department: '', role: '' })

  const create = useMutation({
    mutationFn: () => api.owners.create({
      name: form.name,
      email: form.email || null,
      team: form.team || null,
      department: form.department || null,
      role: form.role || null,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['owners'] })
      setForm({ name: '', email: '', team: '', department: '', role: '' })
    },
  })

  const del = useMutation({
    mutationFn: (id: string) => api.owners.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['owners'] }),
  })

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold flex items-center gap-2"><User size={18} /> Owner verwalten</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 text-xl">×</button>
        </div>

        {/* Neuer Owner */}
        <div className="grid grid-cols-2 gap-2 mb-4">
          <input
            className="col-span-2 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-100 focus:outline-none"
            placeholder="Name *"
            value={form.name}
            onChange={e => setForm({ ...form, name: e.target.value })}
          />
          <input
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
            placeholder="E-Mail"
            value={form.email}
            onChange={e => setForm({ ...form, email: e.target.value })}
          />
          <input
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
            placeholder="Team"
            value={form.team}
            onChange={e => setForm({ ...form, team: e.target.value })}
          />
          <input
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
            placeholder="Abteilung"
            value={form.department}
            onChange={e => setForm({ ...form, department: e.target.value })}
          />
          <input
            className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 focus:outline-none"
            placeholder="Rolle (Owner/Operator/…)"
            value={form.role}
            onChange={e => setForm({ ...form, role: e.target.value })}
          />
          <button
            onClick={() => create.mutate()}
            disabled={!form.name}
            className="col-span-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-sm py-2 rounded"
          >
            Owner anlegen
          </button>
        </div>

        {/* Owner-Liste */}
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {owners.map((o: Owner) => (
            <div key={o.id} className="flex items-center gap-3 bg-gray-800 rounded-lg px-3 py-2">
              <div className="flex-1">
                <div className="text-sm font-medium">{o.name}</div>
                <div className="text-xs text-gray-500 flex gap-2">
                  {o.team && <span>{o.team}</span>}
                  {o.department && <span>{o.department}</span>}
                  {o.email && <span>{o.email}</span>}
                </div>
              </div>
              <button onClick={() => del.mutate(o.id)} className="text-gray-600 hover:text-red-400">
                <Trash2 size={13} />
              </button>
            </div>
          ))}
          {owners.length === 0 && <p className="text-xs text-gray-600 text-center py-2">Keine Owners</p>}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Prozess-Zeile
// ---------------------------------------------------------------------------

type ViewMode = 'basis' | 'risk' | 'apps'

function ProcessRow({ process }: { process: any }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [view, setView] = useState<ViewMode>('basis')

  const { data: owners = [] } = useQuery({ queryKey: ['owners'], queryFn: api.owners.list })

  const { data: risk } = useQuery({
    queryKey: ['process-risk', process.id],
    queryFn: () => api.processes.risk(process.id),
    enabled: open && view === 'risk',
  })

  const { data: assets = [] } = useQuery({
    queryKey: ['process-assets', process.id],
    queryFn: () => api.processes.assets(process.id),
    enabled: open && view === 'risk',
  })

  const { data: basis } = useQuery({
    queryKey: ['basis', process.id],
    queryFn: () => fetchObashi(process.id),
    enabled: open && view === 'basis',
  })

  // Owner zuweisen
  const setOwner = useMutation({
    mutationFn: (ownerId: string | null) => api.processes.update(process.id, {
      name: process.name,
      criticality: process.criticality,
      owner_id: ownerId,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['processes'] })
      qc.invalidateQueries({ queryKey: ['basis', process.id] })
    },
  })

  const currentOwner = owners.find((o: Owner) => o.id === process.owner_id)

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 px-4 py-3 hover:bg-gray-800 transition-colors"
      >
        <div className="flex-1 text-left">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm">{process.name}</span>
            {currentOwner && (
              <span className="flex items-center gap-1 text-xs bg-indigo-900/50 text-indigo-400 px-2 py-0.5 rounded-full border border-indigo-800">
                <User size={10} /> {currentOwner.name}
              </span>
            )}
          </div>
          {process.description && (
            <div className="text-xs text-gray-500 mt-0.5 truncate max-w-md">{process.description}</div>
          )}
        </div>
        <div className="flex items-center gap-6 text-xs text-gray-500">
          <div>
            <div className="text-gray-600 mb-1">Kritikalität</div>
            <CriticalityBar value={process.criticality} />
          </div>
          {process.sla_rto_hours && (
            <div>
              <div className="text-gray-600">RTO</div>
              <div>{process.sla_rto_hours}h</div>
            </div>
          )}
        </div>
        {open ? <ChevronUp size={14} className="text-gray-500 shrink-0" /> : <ChevronDown size={14} className="text-gray-500 shrink-0" />}
      </button>

      {open && (
        <div className="border-t border-gray-800">
          {/* Toolbar */}
          <div className="flex items-center gap-3 px-4 pt-3 pb-0">
            <div className="flex gap-1">
              {[
                { id: 'basis', icon: Layers, label: 'BASIS' },
                { id: 'apps', icon: Settings2, label: 'Fachanwendungen' },
                { id: 'risk', icon: BarChart2, label: 'CVE-Risiko' },
              ].map(({ id, icon: Icon, label }) => (
                <button
                  key={id}
                  onClick={() => setView(id as ViewMode)}
                  className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md transition-colors ${
                    view === id ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  <Icon size={12} /> {label}
                </button>
              ))}
            </div>

            {/* Owner-Picker inline */}
            <div className="ml-auto flex items-center gap-2 text-xs text-gray-500">
              <User size={12} />
              <OwnerPicker
                value={process.owner_id ?? null}
                onChange={id => setOwner.mutate(id)}
              />
            </div>
          </div>

          {/* BASIS View */}
          {view === 'basis' && (
            <div className="p-4">
              {!basis && <div className="text-gray-500 text-sm py-4 text-center">Lade…</div>}
              {basis && basis.nodes.length === 0 && (
                <div className="text-gray-600 text-sm py-4 text-center">
                  Keine Daten. Fachanwendungen anlegen und Assets/Netze zuordnen.
                </div>
              )}
              {basis && basis.nodes.length > 0 && (
                <div className="rounded-lg overflow-hidden border border-gray-800">
                  <BasisDiagram data={basis} />
                </div>
              )}
            </div>
          )}

          {/* Applications View */}
          {view === 'apps' && (
            <div className="p-4">
              <ApplicationManager processId={process.id} owners={owners} />
            </div>
          )}

          {/* Risk View */}
          {view === 'risk' && (
            <div className="p-4 grid grid-cols-2 gap-6">
              <div>
                <h3 className="text-xs text-gray-500 uppercase mb-3">CVE-Risiko</h3>
                {!risk ? <div className="text-gray-600 text-sm">Laden…</div> : (
                  <>
                    <div className="grid grid-cols-3 gap-2 mb-4">
                      {[
                        { label: 'HIGH', count: risk.high_risk_count, color: 'text-red-400' },
                        { label: 'MEDIUM', count: risk.medium_risk_count, color: 'text-yellow-400' },
                        { label: 'LOW', count: risk.low_risk_count, color: 'text-green-400' },
                      ].map(({ label, count, color }) => (
                        <div key={label} className="bg-gray-800 rounded p-3 text-center">
                          <div className={`text-2xl font-bold ${color}`}>{count}</div>
                          <div className="text-xs text-gray-500">{label}</div>
                        </div>
                      ))}
                    </div>
                    {risk.top_cves.length > 0 && (
                      <div className="space-y-1">
                        {risk.top_cves.map((c: any) => (
                          <div key={c.cve_id} className="flex items-center justify-between text-xs">
                            <span className="font-mono text-indigo-400">{c.cve_id}</span>
                            <Badge value={c.risk_level} />
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
              <div>
                <h3 className="text-xs text-gray-500 uppercase mb-3">Assets ({assets.length})</h3>
                <div className="space-y-1.5">
                  {assets.map((a: any) => (
                    <div key={a.asset_id} className="flex items-center justify-between bg-gray-800 rounded px-3 py-1.5 text-sm">
                      <span className="font-medium">{a.hostname ?? a.ip_address}</span>
                      <Badge value={a.exposure_level} />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptseite
// ---------------------------------------------------------------------------

function NewProcessModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name: '', description: '', criticality: 3,
    sla_rto_hours: '', sla_rpo_hours: '', owner_id: '' as string | null,
  })
  const [error, setError] = useState('')

  const create = useMutation({
    mutationFn: () => api.processes.create({
      name: form.name,
      description: form.description || null,
      criticality: form.criticality,
      sla_rto_hours: form.sla_rto_hours ? Number(form.sla_rto_hours) : null,
      sla_rpo_hours: form.sla_rpo_hours ? Number(form.sla_rpo_hours) : null,
      owner_id: form.owner_id || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['processes'] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md p-5 space-y-3" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-bold flex items-center gap-2"><Workflow size={18} /> Neuer Prozess</h2>
        <input className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="Name des Prozesses" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} autoFocus />
        <textarea className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none resize-none"
          placeholder="Beschreibung (optional)" rows={2} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
        <div className="grid grid-cols-3 gap-2">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Kritikalität</label>
            <select className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              value={form.criticality} onChange={e => setForm({ ...form, criticality: +e.target.value })}>
              {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}/5</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">RTO (Std.)</label>
            <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              placeholder="4" value={form.sla_rto_hours} onChange={e => setForm({ ...form, sla_rto_hours: e.target.value })} />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">RPO (Std.)</label>
            <input type="number" className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-300 focus:outline-none"
              placeholder="1" value={form.sla_rpo_hours} onChange={e => setForm({ ...form, sla_rpo_hours: e.target.value })} />
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">Owner</label>
          <OwnerPicker value={form.owner_id} onChange={id => setForm({ ...form, owner_id: id })} />
        </div>
        {error && <div className="text-xs text-red-400">{error}</div>}
        <div className="flex gap-2 justify-end pt-1">
          <button onClick={onClose} className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2">Abbrechen</button>
          <button onClick={() => create.mutate()} disabled={!form.name || create.isPending}
            className="flex items-center gap-2 text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-4 py-2 rounded-lg">
            <Plus size={14} /> {create.isPending ? 'Anlegen…' : 'Anlegen'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Processes() {
  const [showOwnerMgmt, setShowOwnerMgmt] = useState(false)
  const [showNewProc, setShowNewProc] = useState(false)
  const { data: processes = [], isLoading } = useQuery({
    queryKey: ['processes'],
    queryFn: api.processes.list,
  })

  return (
    <div className="max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Business-Prozesse</h1>
          <p className="text-sm text-gray-500 mt-1">
            B → A → C → S → H → I
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowOwnerMgmt(true)}
            className="flex items-center gap-2 text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg border border-gray-700"
          >
            <User size={14} /> Owner verwalten
          </button>
          <button
            onClick={() => setShowNewProc(true)}
            className="flex items-center gap-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-2 rounded-lg"
          >
            <Plus size={14} /> Neuer Prozess
          </button>
        </div>
      </div>

      {isLoading && <div className="text-gray-500">Laden…</div>}
      <div className="space-y-3">
        {processes.map((p: any) => <ProcessRow key={p.id} process={p} />)}
        {!isLoading && processes.length === 0 && (
          <div className="text-center bg-gray-900 border border-gray-800 rounded-lg p-8 text-gray-500 text-sm">
            Keine Prozesse vorhanden — oben rechts „Neuer Prozess" anlegen.
          </div>
        )}
      </div>

      {showOwnerMgmt && <OwnerManagement onClose={() => setShowOwnerMgmt(false)} />}
      {showNewProc && <NewProcessModal onClose={() => setShowNewProc(false)} />}
    </div>
  )
}
