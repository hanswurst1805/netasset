import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type User } from '../api/client'
import { Plus, Trash2, Key, Copy, Check } from 'lucide-react'

function TagInput({ tags, onChange }: { tags: string[]; onChange: (t: string[]) => void }) {
  const [input, setInput] = useState('')
  function add() {
    const t = input.trim()
    if (t && !tags.includes(t)) onChange([...tags, t])
    setInput('')
  }
  return (
    <div>
      <div className="flex gap-2 mb-2 flex-wrap">
        {tags.map(t => (
          <span key={t} className="flex items-center gap-1 bg-indigo-900 text-indigo-300 text-xs px-2 py-0.5 rounded">
            {t}
            <button onClick={() => onChange(tags.filter(x => x !== t))} className="hover:text-white">×</button>
          </span>
        ))}
        {tags.length === 0 && <span className="text-xs text-gray-600">Kein Tag = sieht alles</span>}
      </div>
      <div className="flex gap-2">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none"
          placeholder="Tag hinzufügen..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), add())}
        />
        <button onClick={add} className="text-xs bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded">+</button>
      </div>
    </div>
  )
}

function NewUserForm({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ username: '', password: '', role: 'user', allowed_tags: [] as string[] })
  const [error, setError] = useState('')

  const create = useMutation({
    mutationFn: () => api.auth.users.create(form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['users'] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-3">
      <h3 className="text-sm font-semibold">Neuer User</h3>
      <input
        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
        placeholder="Benutzername"
        value={form.username}
        onChange={e => setForm({ ...form, username: e.target.value })}
      />
      <input
        type="password"
        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
        placeholder="Passwort"
        value={form.password}
        onChange={e => setForm({ ...form, password: e.target.value })}
      />
      <select
        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-300 focus:outline-none"
        value={form.role}
        onChange={e => setForm({ ...form, role: e.target.value })}
      >
        <option value="user">user</option>
        <option value="admin">admin</option>
      </select>
      <div>
        <div className="text-xs text-gray-400 mb-1.5">Erlaubte Tags (leer = alle)</div>
        <TagInput tags={form.allowed_tags} onChange={t => setForm({ ...form, allowed_tags: t })} />
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}
      <div className="flex gap-2 justify-end">
        <button onClick={onClose} className="text-xs text-gray-400 hover:text-gray-200 px-3 py-1.5">Abbrechen</button>
        <button
          onClick={() => create.mutate()}
          disabled={!form.username || !form.password}
          className="text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded"
        >
          Anlegen
        </button>
      </div>
    </div>
  )
}

function APIKeySection() {
  const { data: keys = [], error: listError } = useQuery({ queryKey: ['apikeys'], queryFn: api.auth.apiKeys.list })
  const qc = useQueryClient()
  const [newKey, setNewKey] = useState<{ raw_key: string; name: string } | null>(null)
  const [name, setName] = useState('')
  const [copied, setCopied] = useState(false)
  const [createError, setCreateError] = useState('')

  const create = useMutation({
    mutationFn: () => api.auth.apiKeys.create({ name }),
    onSuccess: (k: any) => {
      qc.invalidateQueries({ queryKey: ['apikeys'] })
      setNewKey(k)
      setName('')
      setCreateError('')
    },
    onError: (e: Error) => setCreateError(e.message),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.auth.apiKeys.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['apikeys'] }),
  })

  function copy(text: string) {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2">
        <Key size={12} /> API Keys
      </h2>

      {newKey && (
        <div className="bg-green-950 border-2 border-green-600 rounded-xl p-4 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-green-400 font-bold text-sm">⚠ Jetzt kopieren — wird danach nicht mehr angezeigt!</span>
          </div>
          <div className="bg-gray-900 border border-green-700 rounded-lg p-3 mb-3">
            <div className="text-xs text-gray-500 mb-1">Vollständiger API-Key:</div>
            <div className="flex items-center gap-3">
              <code className="flex-1 text-green-300 text-sm font-mono break-all select-all">
                {newKey.raw_key}
              </code>
              <button
                onClick={() => copy(newKey.raw_key)}
                className={`shrink-0 flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  copied
                    ? 'bg-green-600 text-white'
                    : 'bg-indigo-600 hover:bg-indigo-500 text-white'
                }`}
              >
                {copied ? <><Check size={14} /> Kopiert!</> : <><Copy size={14} /> Kopieren</>}
              </button>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500">
              Eintragen in: <code className="text-gray-400">netasset_collector.conf → api_key = ...</code>
            </span>
            <button
              onClick={() => setNewKey(null)}
              className="text-xs text-gray-500 hover:text-red-400 border border-gray-700 hover:border-red-700 rounded px-2 py-1 transition-colors"
            >
              Ich habe den Key kopiert — Schließen
            </button>
          </div>
        </div>
      )}

      <div className="flex gap-2 mb-2">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
          placeholder="Name des API-Keys (z.B. linux-server)"
          value={name}
          onChange={e => { setName(e.target.value); setCreateError('') }}
          onKeyDown={e => e.key === 'Enter' && name && create.mutate()}
        />
        <button
          onClick={() => create.mutate()}
          disabled={!name || create.isPending}
          className="flex items-center gap-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-sm text-gray-200 px-3 py-1.5 rounded whitespace-nowrap"
        >
          <Plus size={14} /> {create.isPending ? 'Erstelle…' : 'Key erstellen'}
        </button>
      </div>
      {createError && (
        <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-2 py-1 mb-2">{createError}</p>
      )}
      {listError && (
        <p className="text-xs text-red-400 mb-2">Fehler beim Laden: {(listError as Error).message}</p>
      )}

      {/* Key-Tabelle */}
      {keys.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">Präfix</th>
                <th className="text-left px-4 py-2">Tags</th>
                <th className="text-left px-4 py-2">Zuletzt benutzt</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k: any) => (
                <tr key={k.id} className="border-b border-gray-800 last:border-0">
                  <td className="px-4 py-3 font-medium">{k.name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-indigo-400">
                    {k.key_prefix}…
                  </td>
                  <td className="px-4 py-3">
                    {k.allowed_tags?.length > 0
                      ? <div className="flex gap-1 flex-wrap">
                          {k.allowed_tags.map((t: string) => (
                            <span key={t} className="text-xs bg-indigo-900/50 text-indigo-400 border border-indigo-800 px-2 py-0.5 rounded">{t}</span>
                          ))}
                        </div>
                      : <span className="text-xs text-gray-600">alle</span>
                    }
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {k.last_used_at
                      ? new Date(k.last_used_at).toLocaleString('de', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })
                      : <span className="text-gray-700">nie</span>
                    }
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${k.is_active ? 'bg-green-900/50 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                      {k.is_active ? 'aktiv' : 'inaktiv'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => revoke.mutate(k.id)}
                      className="text-gray-600 hover:text-red-400 transition-colors"
                      title="Löschen"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {keys.length === 0 && !listError && (
        <p className="text-xs text-gray-600 py-2">Keine API-Keys vorhanden</p>
      )}
    </div>
  )
}

export default function UserManagement() {
  const qc = useQueryClient()
  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: api.auth.users.list })
  const [showNew, setShowNew] = useState(false)

  const del = useMutation({
    mutationFn: (id: string) => api.auth.users.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  const isAdmin = localStorage.getItem('role') === 'admin'

  return (
    <div className="max-w-3xl space-y-8">
      <h1 className="text-2xl font-bold">Einstellungen</h1>

      {isAdmin && (
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Benutzer</h2>
            <button
              onClick={() => setShowNew(!showNew)}
              className="flex items-center gap-1 text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded"
            >
              <Plus size={12} /> Neuer User
            </button>
          </div>

          {showNew && <div className="mb-3"><NewUserForm onClose={() => setShowNew(false)} /></div>}

          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                  <th className="text-left px-4 py-2">User</th>
                  <th className="text-left px-4 py-2">Rolle</th>
                  <th className="text-left px-4 py-2">Tags</th>
                  <th className="px-4 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {users.map((u: User) => (
                  <tr key={u.id} className="border-b border-gray-800">
                    <td className="px-4 py-2">
                      <div className="font-medium">{u.username}</div>
                      {u.email && <div className="text-xs text-gray-500">{u.email}</div>}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        u.role === 'admin'
                          ? 'bg-indigo-900 text-indigo-300'
                          : 'bg-gray-800 text-gray-400'
                      }`}>{u.role}</span>
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex gap-1 flex-wrap">
                        {u.allowed_tags.length === 0
                          ? <span className="text-xs text-gray-600">alle</span>
                          : u.allowed_tags.map(t => (
                            <span key={t} className="text-xs bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded">{t}</span>
                          ))
                        }
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => del.mutate(u.id)}
                        className="text-gray-600 hover:text-red-400 transition-colors"
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section>
        <APIKeySection />
      </section>
    </div>
  )
}
