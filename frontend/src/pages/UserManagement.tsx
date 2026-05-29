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
  const { data: keys = [] } = useQuery({ queryKey: ['apikeys'], queryFn: api.auth.apiKeys.list })
  const qc = useQueryClient()
  const [newKey, setNewKey] = useState<{ raw_key: string; name: string } | null>(null)
  const [name, setName] = useState('')
  const [copied, setCopied] = useState(false)

  const create = useMutation({
    mutationFn: () => api.auth.apiKeys.create({ name }),
    onSuccess: (k: any) => { qc.invalidateQueries({ queryKey: ['apikeys'] }); setNewKey(k); setName('') },
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
        <div className="bg-green-950 border border-green-800 rounded-lg p-3 mb-3 text-sm">
          <p className="text-green-400 font-medium mb-2">Key einmalig kopieren!</p>
          <div className="flex items-center gap-2 font-mono text-xs bg-gray-900 rounded px-3 py-2">
            <span className="flex-1 text-green-300 truncate">{newKey.raw_key}</span>
            <button onClick={() => copy(newKey.raw_key)} className="text-gray-400 hover:text-white">
              {copied ? <Check size={14} /> : <Copy size={14} />}
            </button>
          </div>
          <button onClick={() => setNewKey(null)} className="text-xs text-gray-500 mt-2">Schließen</button>
        </div>
      )}

      <div className="flex gap-2 mb-3">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none"
          placeholder="Name des API-Keys"
          value={name}
          onChange={e => setName(e.target.value)}
        />
        <button
          onClick={() => create.mutate()}
          disabled={!name}
          className="flex items-center gap-1 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-sm text-gray-200 px-3 py-1.5 rounded"
        >
          <Plus size={14} /> Key erstellen
        </button>
      </div>

      <div className="space-y-2">
        {keys.map(k => (
          <div key={k.id} className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
            <div>
              <span className="text-sm font-medium">{k.name}</span>
              <span className="text-xs text-gray-500 ml-2 font-mono">{k.key_prefix}…</span>
              {k.last_used_at && (
                <span className="text-xs text-gray-600 ml-2">
                  zuletzt: {new Date(k.last_used_at).toLocaleDateString('de')}
                </span>
              )}
            </div>
            <button
              onClick={() => revoke.mutate(k.id)}
              className="text-gray-600 hover:text-red-400 transition-colors"
            >
              <Trash2 size={14} />
            </button>
          </div>
        ))}
        {keys.length === 0 && <p className="text-xs text-gray-600">Keine API-Keys</p>}
      </div>
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
