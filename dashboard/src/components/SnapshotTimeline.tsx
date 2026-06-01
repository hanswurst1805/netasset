import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { History, Plus, Minus, ArrowRight } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function fetchSnapshots(assetId: string) {
  const res = await fetch(`/api/v1/snapshots/assets/${assetId}`, {
    headers: { Authorization: `Bearer ${token()}` },
  })
  if (!res.ok) throw new Error('Snapshots konnten nicht geladen werden')
  return res.json()
}

async function createSnapshot(assetId: string) {
  const res = await fetch(`/api/v1/snapshots/assets/${assetId}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token()}` },
  })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

interface Snapshot {
  id: string
  snapshot_date: string
  data: Record<string, any>
  diff: Record<string, any> | null
  has_changes: boolean
}

// ---------------------------------------------------------------------------
// Diff-Anzeige
// ---------------------------------------------------------------------------

function DiffSection({ title, items, type }: {
  title: string
  items: any[]
  type: 'added' | 'removed' | 'changed'
}) {
  if (!items || items.length === 0) return null
  const colors = {
    added:   'text-green-400 bg-green-950 border-green-800',
    removed: 'text-red-400 bg-red-950 border-red-800',
    changed: 'text-yellow-400 bg-yellow-950 border-yellow-800',
  }
  return (
    <div className={`rounded-lg border p-3 ${colors[type]}`}>
      <div className="flex items-center gap-2 text-xs font-semibold mb-2 uppercase tracking-wider">
        {type === 'added' && <Plus size={12} />}
        {type === 'removed' && <Minus size={12} />}
        {type === 'changed' && <ArrowRight size={12} />}
        {title}
      </div>
      <div className="space-y-1 text-xs">
        {items.map((item, i) => (
          <div key={i} className="font-mono">
            {typeof item === 'string' ? item :
             item.pkg_name ? `${item.pkg_name} ${item.pkg_version}` :
             item.port ? `Port ${item.port}/${item.proto}` :
             JSON.stringify(item)}
          </div>
        ))}
      </div>
    </div>
  )
}

function ChangedFields({ changed }: { changed: Record<string, { from: any; to: any }> }) {
  if (!changed || Object.keys(changed).length === 0) return null
  return (
    <div className="rounded-lg border border-yellow-800 bg-yellow-950 p-3">
      <div className="flex items-center gap-2 text-xs font-semibold mb-2 uppercase tracking-wider text-yellow-400">
        <ArrowRight size={12} /> Geändert
      </div>
      <div className="space-y-1">
        {Object.entries(changed).map(([key, { from, to }]) => (
          <div key={key} className="text-xs flex items-center gap-2">
            <span className="text-yellow-600 w-28 shrink-0">{key}</span>
            <span className="text-red-400 line-through">{String(from ?? '—')}</span>
            <ArrowRight size={10} className="text-yellow-600 shrink-0" />
            <span className="text-green-400">{String(to ?? '—')}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function DiffView({ diff }: { diff: Record<string, any> | null }) {
  if (!diff || Object.keys(diff).length === 0) {
    return <p className="text-xs text-gray-600 italic">Keine Änderungen gegenüber dem Vortag</p>
  }

  return (
    <div className="space-y-2">
      <ChangedFields changed={diff.changed ?? {}} />
      <DiffSection title="SBOM hinzugefügt" items={diff.added?.sbom ?? []} type="added" />
      <DiffSection title="SBOM entfernt" items={diff.removed?.sbom ?? []} type="removed" />
      <DiffSection title="Ports hinzugefügt" items={diff.added?.open_ports ?? []} type="added" />
      <DiffSection title="Ports entfernt" items={diff.removed?.open_ports ?? []} type="removed" />
      <DiffSection title="Tags hinzugefügt" items={diff.added?.tags ?? []} type="added" />
      <DiffSection title="Tags entfernt" items={diff.removed?.tags ?? []} type="removed" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Hauptkomponente
// ---------------------------------------------------------------------------

export default function SnapshotTimeline({ assetId }: { assetId: string }) {
  const [selected, setSelected] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: snapshots = [], refetch, isLoading } = useQuery({
    queryKey: ['snapshots', assetId],
    queryFn: () => fetchSnapshots(assetId),
  })

  async function handleCreate() {
    setCreating(true)
    try { await createSnapshot(assetId); refetch() }
    catch (e) { alert((e as Error).message) }
    finally { setCreating(false) }
  }

  const selectedSnap = snapshots.find((s: Snapshot) => s.id === selected)

  if (isLoading) return <div className="text-gray-600 text-sm py-4">Laden…</div>

  return (
    <div className="flex gap-6">
      {/* Timeline links */}
      <div className="w-52 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            {snapshots.length} Snapshots
          </span>
          <button
            onClick={handleCreate}
            disabled={creating}
            className="flex items-center gap-1 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-gray-300 px-2 py-1 rounded"
          >
            <History size={11} /> {creating ? '…' : 'Jetzt'}
          </button>
        </div>

        {snapshots.length === 0 && (
          <p className="text-xs text-gray-600">
            Noch keine Snapshots — „Jetzt" klicken um den ersten zu erstellen
          </p>
        )}

        <div className="space-y-1 max-h-96 overflow-y-auto">
          {snapshots.map((snap: Snapshot) => {
            const d = new Date(snap.snapshot_date)
            const label = d.toLocaleDateString('de', { day: '2-digit', month: '2-digit', year: '2-digit' })
            const isSelected = snap.id === selected
            return (
              <button
                key={snap.id}
                onClick={() => setSelected(isSelected ? null : snap.id)}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs transition-colors ${
                  isSelected
                    ? 'bg-indigo-600 text-white'
                    : 'hover:bg-gray-800 text-gray-400'
                }`}
              >
                {/* Änderungs-Indikator */}
                <span className={`w-2 h-2 rounded-full shrink-0 ${
                  snap.has_changes ? 'bg-yellow-500' : 'bg-gray-600'
                }`} />
                <span className="font-mono">{label}</span>
                {snap.has_changes && !isSelected && (
                  <span className="ml-auto text-yellow-500 text-xs">●</span>
                )}
              </button>
            )
          })}
        </div>

        <div className="mt-3 text-xs text-gray-700">
          ● = Änderungen vorhanden
        </div>
      </div>

      {/* Detail rechts */}
      <div className="flex-1 min-w-0">
        {!selectedSnap ? (
          <div className="text-gray-600 text-sm py-4">
            Datum auswählen um Details und Änderungen zu sehen
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-sm">
                {new Date(selectedSnap.snapshot_date).toLocaleDateString('de', {
                  weekday: 'long', day: '2-digit', month: 'long', year: 'numeric'
                })}
              </h3>
              <span className={`text-xs px-2 py-0.5 rounded ${
                selectedSnap.has_changes
                  ? 'bg-yellow-900 text-yellow-400'
                  : 'bg-gray-800 text-gray-500'
              }`}>
                {selectedSnap.has_changes ? 'Änderungen' : 'Unverändert'}
              </span>
            </div>

            {/* Diff */}
            {selectedSnap.diff !== undefined && (
              <div>
                <div className="text-xs text-gray-500 mb-2 uppercase tracking-wider">
                  Änderungen gegenüber Vortag
                </div>
                <DiffView diff={selectedSnap.diff} />
              </div>
            )}

            {/* Zustand an diesem Tag */}
            <details className="group">
              <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-300 list-none flex items-center gap-1">
                <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
                Vollständiger Zustand am {new Date(selectedSnap.snapshot_date).toLocaleDateString('de')}
              </summary>
              <div className="mt-2 bg-gray-900 border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-400 max-h-64 overflow-y-auto">
                <div className="space-y-1">
                  {Object.entries(selectedSnap.data).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <span className="text-gray-600 w-32 shrink-0">{k}</span>
                      <span className="break-all">
                        {Array.isArray(v)
                          ? v.length === 0 ? '—' : `[${v.length} Einträge]`
                          : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </details>
          </div>
        )}
      </div>
    </div>
  )
}
