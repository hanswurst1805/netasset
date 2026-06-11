import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import Badge from '../components/Badge'
import { Search, Trash2, ChevronDown, ChevronUp, AlertTriangle } from 'lucide-react'
import LastSeen from '../components/LastSeen'

const TYPES = ['', 'server', 'switch', 'router', 'firewall', 'client']
const EXPOSURES = ['', 'INTERN', 'DMZ', 'EXTERN']

// Vordefinierte Tag-Vorschläge (plus alle Tags aus den geladenen Assets)
const KNOWN_TAGS = ['reboot-required', 'stale', 'unmanaged', 'test', 'prod', 'dev']

interface BulkFilter {
  lastSeenDays: string      // "" | "7" | "30" | "90" | "180" | "365"
  neverSeen: boolean
  tags: string[]
}

function BulkDeletePanel({ allTags }: { allTags: string[] }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState<BulkFilter>({ lastSeenDays: '', neverSeen: false, tags: [] })
  const [preview, setPreview] = useState<{ matched: number } | null>(null)
  const [confirmStep, setConfirmStep] = useState(false)
  const [tagInput, setTagInput] = useState('')

  const hasFilter = filter.lastSeenDays || filter.neverSeen || filter.tags.length > 0

  const previewMut = useMutation({
    mutationFn: () => api.assets.bulkDelete({
      last_seen_before_days: filter.lastSeenDays ? parseInt(filter.lastSeenDays) : null,
      never_seen: filter.neverSeen,
      tags: filter.tags.length ? filter.tags : undefined,
      dry_run: true,
    }),
    onSuccess: (data) => {
      setPreview({ matched: data.matched })
      setConfirmStep(false)
    },
  })

  const deleteMut = useMutation({
    mutationFn: () => api.assets.bulkDelete({
      last_seen_before_days: filter.lastSeenDays ? parseInt(filter.lastSeenDays) : null,
      never_seen: filter.neverSeen,
      tags: filter.tags.length ? filter.tags : undefined,
      dry_run: false,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setPreview(null)
      setConfirmStep(false)
      setFilter({ lastSeenDays: '', neverSeen: false, tags: [] })
    },
  })

  const toggleTag = (tag: string) => {
    setFilter(f => ({
      ...f,
      tags: f.tags.includes(tag) ? f.tags.filter(t => t !== tag) : [...f.tags, tag],
    }))
    setPreview(null)
  }

  const addCustomTag = () => {
    const t = tagInput.trim()
    if (t && !filter.tags.includes(t)) toggleTag(t)
    setTagInput('')
  }

  const suggestions = [...new Set([...KNOWN_TAGS, ...allTags])].sort()

  return (
    <div className="mb-6 bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
      {/* Header */}
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-sm text-gray-400 hover:text-gray-200 hover:bg-gray-800 transition-colors"
        onClick={() => { setOpen(o => !o); setPreview(null); setConfirmStep(false) }}
      >
        <span className="flex items-center gap-2">
          <Trash2 size={14} className="text-red-500" />
          <span className="font-medium">Bulk-Löschung</span>
          <span className="text-xs text-gray-600">Assets nach Filterkriterien deaktivieren</span>
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-gray-800 pt-4 space-y-4">
          {/* Filter: Zuletzt gesehen */}
          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium uppercase tracking-wider">
              Zuletzt gesehen
            </label>
            <div className="flex gap-2 flex-wrap">
              {[
                { label: 'Egal', value: '' },
                { label: '> 4 Tage', value: '4' },
                { label: '> 7 Tage', value: '7' },
                { label: '> 30 Tage', value: '30' },
                { label: '> 90 Tage', value: '90' },
                { label: '> 180 Tage', value: '180' },
                { label: '> 1 Jahr', value: '365' },
              ].map(o => (
                <button
                  key={o.value}
                  onClick={() => { setFilter(f => ({ ...f, lastSeenDays: o.value })); setPreview(null) }}
                  className={`px-3 py-1 rounded text-xs border transition-colors ${
                    filter.lastSeenDays === o.value
                      ? 'bg-indigo-700 border-indigo-500 text-white'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  {o.label}
                </button>
              ))}
              <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={filter.neverSeen}
                  onChange={e => { setFilter(f => ({ ...f, neverSeen: e.target.checked })); setPreview(null) }}
                  className="rounded border-gray-600"
                />
                Nie gesehen (last_seen_at leer)
              </label>
            </div>
          </div>

          {/* Filter: Tags */}
          <div>
            <label className="block text-xs text-gray-400 mb-1.5 font-medium uppercase tracking-wider">
              Tags (mindestens einer muss zutreffen)
            </label>
            <div className="flex gap-2 flex-wrap mb-2">
              {suggestions.map(tag => (
                <button
                  key={tag}
                  onClick={() => toggleTag(tag)}
                  className={`px-2 py-0.5 rounded text-xs border transition-colors ${
                    filter.tags.includes(tag)
                      ? 'bg-indigo-700 border-indigo-500 text-white'
                      : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
                  }`}
                >
                  {tag}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500 w-40"
                placeholder="Eigener Tag…"
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addCustomTag()}
              />
              <button
                onClick={addCustomTag}
                className="px-2 py-1 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded border border-gray-600"
              >
                + Hinzufügen
              </button>
            </div>
          </div>

          {/* Aktionen */}
          {!confirmStep ? (
            <div className="flex items-center gap-3">
              <button
                disabled={!hasFilter || previewMut.isPending}
                onClick={() => { setConfirmStep(false); previewMut.mutate() }}
                className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-200 rounded border border-gray-600 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {previewMut.isPending ? 'Prüfe…' : 'Vorschau'}
              </button>

              {preview !== null && (
                <span className={`text-sm font-medium ${preview.matched === 0 ? 'text-gray-500' : 'text-amber-400'}`}>
                  {preview.matched === 0
                    ? 'Keine Assets betroffen'
                    : `${preview.matched} Asset${preview.matched !== 1 ? 's' : ''} betroffen`}
                </span>
              )}

              {preview !== null && preview.matched > 0 && (
                <button
                  onClick={() => setConfirmStep(true)}
                  className="px-3 py-1.5 text-xs bg-red-800 hover:bg-red-700 text-red-100 rounded border border-red-700 flex items-center gap-1"
                >
                  <Trash2 size={12} /> Löschen
                </button>
              )}
            </div>
          ) : (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3">
              <div className="flex items-start gap-2 mb-3">
                <AlertTriangle size={16} className="text-red-400 mt-0.5 shrink-0" />
                <p className="text-sm text-red-200">
                  <strong>{preview?.matched} Assets</strong> werden dauerhaft deaktiviert.
                  Diese Aktion kann nicht rückgängig gemacht werden.
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => deleteMut.mutate()}
                  disabled={deleteMut.isPending}
                  className="px-3 py-1.5 text-xs bg-red-700 hover:bg-red-600 text-white rounded font-medium disabled:opacity-50"
                >
                  {deleteMut.isPending ? 'Lösche…' : `Ja, ${preview?.matched} Assets löschen`}
                </button>
                <button
                  onClick={() => setConfirmStep(false)}
                  className="px-3 py-1.5 text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 rounded"
                >
                  Abbrechen
                </button>
              </div>
            </div>
          )}

          {deleteMut.isSuccess && (
            <p className="text-xs text-green-400">
              ✓ {deleteMut.data?.deleted} Assets erfolgreich deaktiviert.
            </p>
          )}
          {(previewMut.isError || deleteMut.isError) && (
            <p className="text-xs text-red-400">
              Fehler: {((previewMut.error || deleteMut.error) as Error)?.message}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

export default function Assets() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [expFilter, setExpFilter] = useState('')
  const [attentionFilter, setAttentionFilter] = useState(false)
  const [confirmId, setConfirmId] = useState<string | null>(null)

  const del = useMutation({
    mutationFn: (id: string) => api.assets.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setConfirmId(null)
    },
  })

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['assets', typeFilter, expFilter, attentionFilter],
    queryFn: () => api.assets.list({
      ...(typeFilter && { asset_type: typeFilter }),
      ...(expFilter && { exposure_level: expFilter }),
      ...(attentionFilter && { needs_attention: 'true' }),
    }),
  })

  const filtered = assets.filter(a =>
    !search || [a.hostname, a.ip_address, a.fqdn].some(v =>
      v?.toLowerCase().includes(search.toLowerCase())
    )
  )

  // Alle Tags aus geladenen Assets sammeln
  const allTags = [...new Set(assets.flatMap(a => a.tags ?? []))].sort()

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Assets</h1>

      {/* Bulk-Delete Panel */}
      <BulkDeletePanel allTags={allTags} />

      {/* Filter Bar */}
      <div className="flex gap-3 mb-4">
        <div className="relative flex-1 max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="w-full bg-gray-800 border border-gray-700 rounded-md pl-8 pr-3 py-1.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            placeholder="Hostname, IP, FQDN..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
        >
          {TYPES.map(t => <option key={t} value={t}>{t || 'Alle Typen'}</option>)}
        </select>
        <select
          className="bg-gray-800 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
          value={expFilter}
          onChange={e => setExpFilter(e.target.value)}
        >
          {EXPOSURES.map(e => <option key={e} value={e}>{e || 'Alle Exposures'}</option>)}
        </select>
        <button
          onClick={() => setAttentionFilter(a => !a)}
          title="Nur Systeme mit kritischen CVEs, ausstehenden Updates/Reboot oder ohne aktuelle Sichtung anzeigen"
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm border transition-colors ${
            attentionFilter
              ? 'bg-amber-900/50 border-amber-600 text-amber-300'
              : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
          }`}
        >
          <AlertTriangle size={14} />
          Aufmerksamkeit erforderlich
        </button>
      </div>

      {/* Table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase tracking-wider">
              <th className="text-left px-4 py-3">Hostname / IP</th>
              <th className="text-left px-4 py-3">Typ</th>
              <th className="text-left px-4 py-3">OS</th>
              <th className="text-left px-4 py-3">Exposure</th>
              <th className="text-left px-4 py-3">Tags</th>
              <th className="text-left px-4 py-3">Zuletzt gesehen</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Laden…</td></tr>
            )}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Keine Assets gefunden</td></tr>
            )}
            {filtered.map(asset => (
              <tr
                key={asset.id}
                className="group border-b border-gray-800 hover:bg-gray-800 transition-colors"
              >
                <td className="px-4 py-3 cursor-pointer" onClick={() => navigate(`/assets/${asset.id}`)}>
                  <div className="font-medium text-gray-100 flex items-center gap-1.5">
                    {asset.needs_attention && (
                      <span title={asset.attention_reasons?.join(', ')} className="shrink-0">
                        <AlertTriangle size={14} className="text-amber-400" />
                      </span>
                    )}
                    {asset.hostname ?? '—'}
                  </div>
                  <div className="text-xs text-gray-500">{asset.ip_address}</div>
                </td>
                <td className="px-4 py-3 text-gray-400 cursor-pointer" onClick={() => navigate(`/assets/${asset.id}`)}>{asset.asset_type}</td>
                <td className="px-4 py-3 text-gray-400 cursor-pointer" onClick={() => navigate(`/assets/${asset.id}`)}>
                  {asset.os_name} {asset.os_version}
                </td>
                <td className="px-4 py-3 cursor-pointer" onClick={() => navigate(`/assets/${asset.id}`)}>
                  <Badge value={asset.exposure_level} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {asset.tags?.slice(0, 3).map(tag => {
                      if (tag === 'reboot-required')
                        return <span key={tag} className="text-xs bg-red-900/70 text-red-300 px-1.5 py-0.5 rounded">🔄</span>
                      if (tag.startsWith('security-updates:'))
                        return <span key={tag} className="text-xs bg-orange-900/70 text-orange-300 px-1.5 py-0.5 rounded">🔒{tag.split(':')[1]}</span>
                      if (tag.startsWith('updates:'))
                        return <span key={tag} className="text-xs bg-yellow-900/50 text-yellow-400 px-1.5 py-0.5 rounded">⬆{tag.split(':')[1]}</span>
                      return <span key={tag} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{tag}</span>
                    })}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <LastSeen date={(asset as any).last_seen_at} />
                </td>
                <td className="px-4 py-3 text-right">
                  {confirmId === asset.id ? (
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => del.mutate(asset.id)}
                        className="text-xs bg-red-600 hover:bg-red-500 text-white px-2 py-0.5 rounded"
                      >Ja</button>
                      <button
                        onClick={() => setConfirmId(null)}
                        className="text-xs text-gray-500 hover:text-gray-300"
                      >Nein</button>
                    </div>
                  ) : (
                    <button
                      onClick={e => { e.stopPropagation(); setConfirmId(asset.id) }}
                      className="text-gray-600 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-4 py-2 text-xs text-gray-600 border-t border-gray-800">
          {filtered.length} Assets
        </div>
      </div>
    </div>
  )
}
