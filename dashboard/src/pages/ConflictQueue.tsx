import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Plus, Trash2, ChevronDown, ChevronUp } from 'lucide-react'

const BASE = '/api/v1/conflicts'
const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { 'Authorization': `Bearer ${token()}`, 'Content-Type': 'application/json', ...opts?.headers },
  })
  if (!res.ok) throw new Error(await res.text())
  if (res.status === 204) return undefined
  return res.json()
}

export async function fetchConflictCount(): Promise<number> {
  try {
    const stats = await apiFetch('/stats')
    return stats?.pending ?? 0
  } catch { return 0 }
}

interface Conflict {
  id: string
  incoming_data: Record<string, any>
  source: string | null
  confidence: number
  matched_on: string[]
  candidate_asset_id: string | null
  candidate_asset: Record<string, any> | null
  status: string
  created_at: string
}

function DataCard({ title, data, highlight }: { title: string; data: Record<string, any>; highlight?: boolean }) {
  return (
    <div className={`rounded-lg border p-4 flex-1 min-w-0 ${highlight ? 'border-indigo-600 bg-indigo-950/30' : 'border-gray-700 bg-gray-900'}`}>
      <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">{title}</div>
      <div className="space-y-1.5 text-sm">
        {[
          ['Hostname', data.hostname],
          ['IP', data.ip_address],
          ['MAC', data.mac_address],
          ['Typ', data.asset_type],
          ['OS', data.os_name ? `${data.os_name} ${data.os_version ?? ''}` : null],
          ['Exposure', data.exposure_level],
          ['Quelle', data.source],
        ].map(([label, value]) => value ? (
          <div key={label as string} className="flex gap-2">
            <span className="text-gray-500 w-20 shrink-0">{label}</span>
            <span className="text-gray-200 truncate">{value as string}</span>
          </div>
        ) : null)}
        {data.tags?.length > 0 && (
          <div className="flex gap-1 flex-wrap pt-1">
            {data.tags.map((t: string) => (
              <span key={t} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{t}</span>
            ))}
          </div>
        )}
        {data.sources && (
          <div className="text-xs text-gray-600 pt-1">
            Quellen: {data.sources.map((s: any) => s.origin).join(', ')}
          </div>
        )}
      </div>
    </div>
  )
}

function ConflictRow({ conflict }: { conflict: Conflict }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [mergeAssetId, setMergeAssetId] = useState(conflict.candidate_asset_id ?? '')
  const [error, setError] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)

  const mutOpts = {
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['conflicts'] }); qc.invalidateQueries({ queryKey: ['conflict-stats'] }) },
    onError: (e: Error) => setError(e.message),
  }

  const merge   = useMutation({ mutationFn: () => apiFetch(`/${conflict.id}/merge?asset_id=${mergeAssetId}`, { method: 'POST' }), ...mutOpts })
  const create  = useMutation({ mutationFn: () => apiFetch(`/${conflict.id}/create`, { method: 'POST' }), ...mutOpts })
  const discard = useMutation({ mutationFn: () => apiFetch(`/${conflict.id}/discard`, { method: 'POST' }), ...mutOpts })
  const del     = useMutation({ mutationFn: () => apiFetch(`/${conflict.id}`, { method: 'DELETE' }), ...mutOpts })

  const inc = conflict.incoming_data
  const label = inc.hostname || inc.ip_address || inc.mac_address || '(unbekannt)'

  return (
    <div className="bg-gray-900 border border-yellow-800/60 rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-3 hover:bg-gray-800 transition-colors">
        <button onClick={() => setOpen(!open)} className="flex items-center gap-3 flex-1 min-w-0 text-left">
          <AlertTriangle size={14} className="text-yellow-500 shrink-0" />
          <div className="flex-1 min-w-0">
            <span className="font-medium text-sm">{label}</span>
            <span className="text-xs text-gray-500 ml-3">
              Quelle: {conflict.source ?? '?'} · Konfidenz: {(conflict.confidence * 100).toFixed(0)}% ·
              Match auf: {conflict.matched_on.join(', ')}
            </span>
          </div>
          <span className="text-xs text-gray-600 shrink-0">
            {new Date(conflict.created_at).toLocaleString('de')}
          </span>
          {open ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
        </button>

        {/* Löschen-Button */}
        <div className="shrink-0 flex items-center gap-1 ml-2">
          {confirmDelete ? (
            <>
              <button
                onClick={() => del.mutate()}
                disabled={del.isPending}
                className="text-xs bg-red-700 hover:bg-red-600 text-white px-2 py-0.5 rounded disabled:opacity-50"
              >
                {del.isPending ? '…' : 'Ja'}
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="text-xs text-gray-500 hover:text-gray-300 px-1"
              >
                Nein
              </button>
            </>
          ) : (
            <button
              onClick={e => { e.stopPropagation(); setConfirmDelete(true) }}
              className="text-gray-600 hover:text-red-400 transition-colors p-1 rounded"
              title="Eintrag löschen"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {open && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Datensatz-Vergleich */}
          <div className="flex gap-4">
            <DataCard title="Eingehende Daten (neu)" data={inc} highlight />
            {conflict.candidate_asset
              ? <DataCard title="Möglicher Kandidat (bestehend)" data={conflict.candidate_asset} />
              : <div className="flex-1 border border-dashed border-gray-700 rounded-lg p-4 text-gray-600 text-sm flex items-center justify-center">Kein Kandidat gefunden</div>
            }
          </div>

          {error && <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-3 py-2">{error}</p>}

          {/* Aktionen */}
          <div className="flex flex-wrap gap-3 items-center pt-2 border-t border-gray-800">
            {/* Zusammenführen */}
            <div className="flex gap-2 items-center">
              <input
                className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 w-64 focus:outline-none"
                placeholder="Asset-ID zum Zusammenführen"
                value={mergeAssetId}
                onChange={e => setMergeAssetId(e.target.value)}
              />
              <button
                onClick={() => merge.mutate()}
                disabled={!mergeAssetId || merge.isPending}
                className="flex items-center gap-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded"
              >
                <Check size={12} /> Zusammenführen
              </button>
            </div>

            <button
              onClick={() => create.mutate()}
              disabled={create.isPending}
              className="flex items-center gap-1.5 text-xs bg-green-700 hover:bg-green-600 disabled:opacity-40 text-white px-3 py-1.5 rounded"
            >
              <Plus size={12} /> Als neues Asset anlegen
            </button>

            <button
              onClick={() => discard.mutate()}
              disabled={discard.isPending}
              className="flex items-center gap-1.5 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-gray-300 px-3 py-1.5 rounded ml-auto"
            >
              <Trash2 size={12} /> Verwerfen
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function ConflictQueue() {
  const qc = useQueryClient()
  const isAdmin = localStorage.getItem('role') === 'admin'
  const [statusFilter, setStatusFilter] = useState('pending')
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false)

  const { data: conflicts = [], isLoading } = useQuery({
    queryKey: ['conflicts', statusFilter],
    queryFn: () => apiFetch(`?status=${statusFilter}`),
    refetchInterval: 30_000,
  })

  const deleteAll = useMutation({
    mutationFn: () => apiFetch(`?status=${statusFilter}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['conflicts'] })
      qc.invalidateQueries({ queryKey: ['conflict-stats'] })
      setConfirmDeleteAll(false)
    },
  })

  return (
    <div className="max-w-5xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <AlertTriangle size={22} className="text-yellow-500" />
            Conflict Queue
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Geräte die nicht eindeutig zugeordnet werden konnten — bitte manuell prüfen
          </p>
        </div>
        <div className="flex items-center gap-3">
          {isAdmin && conflicts.length > 0 && (
            confirmDeleteAll ? (
              <div className="flex items-center gap-2 bg-red-950 border border-red-800 rounded-lg px-3 py-1.5">
                <span className="text-xs text-red-300">Alle {conflicts.length} löschen?</span>
                <button
                  onClick={() => deleteAll.mutate()}
                  disabled={deleteAll.isPending}
                  className="text-xs bg-red-700 hover:bg-red-600 text-white px-2 py-0.5 rounded disabled:opacity-50"
                >
                  {deleteAll.isPending ? '…' : 'Ja'}
                </button>
                <button
                  onClick={() => setConfirmDeleteAll(false)}
                  className="text-xs text-gray-400 hover:text-gray-200"
                >
                  Nein
                </button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmDeleteAll(true)}
                className="flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-red-900 border border-gray-700 hover:border-red-700 text-gray-400 hover:text-red-300 px-3 py-1.5 rounded-lg transition-colors"
              >
                <Trash2 size={13} /> Alle löschen
              </button>
            )
          )}
          <select
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
            value={statusFilter}
            onChange={e => { setStatusFilter(e.target.value); setConfirmDeleteAll(false) }}
          >
            <option value="pending">Offen</option>
            <option value="merged">Zusammengeführt</option>
            <option value="created">Neu angelegt</option>
            <option value="discarded">Verworfen</option>
          </select>
        </div>
      </div>

      {isLoading && <div className="text-gray-500">Laden…</div>}

      <div className="space-y-3">
        {conflicts.map((c: Conflict) => <ConflictRow key={c.id} conflict={c} />)}
        {!isLoading && conflicts.length === 0 && (
          <div className="text-center bg-gray-900 border border-gray-800 rounded-lg p-12">
            <Check size={32} className="text-green-500 mx-auto mb-3" />
            <p className="text-gray-400 font-medium">
              {statusFilter === 'pending' ? 'Keine offenen Konflikte' : 'Keine Einträge'}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
