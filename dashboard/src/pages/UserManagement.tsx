import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type User } from '../api/client'
import { Plus, Trash2, Key, Copy, Check, ShieldCheck, ShieldOff } from 'lucide-react'

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

function GeneralSettingsSection() {
  const qc = useQueryClient()
  const { data: settings } = useQuery({ queryKey: ['app-settings'], queryFn: api.settings.get })

  const update = useMutation({
    mutationFn: (body: Partial<{ hide_vm_microcode_cves: boolean }>) => api.settings.update(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['app-settings'] }),
  })

  if (!settings) return null

  return (
    <div>
      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
        Allgemein
      </h2>
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex items-center justify-between gap-4">
        <div>
          <div className="text-sm font-medium text-gray-200">Microcode-Updates für VMs/VPS ausblenden</div>
          <div className="text-xs text-gray-500 mt-1">
            CVEs zu intel-microcode, amd64-microcode, linux-firmware u.ä. werden auf
            virtuellen Maschinen als nicht exploitierbar herabgestuft, da der
            Hypervisor-Host das Microcode-Update lädt, nicht der Gast.
          </div>
        </div>
        <button
          role="switch"
          aria-checked={settings.hide_vm_microcode_cves}
          onClick={() => update.mutate({ hide_vm_microcode_cves: !settings.hide_vm_microcode_cves })}
          disabled={update.isPending}
          className={`shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
            settings.hide_vm_microcode_cves ? 'bg-indigo-600' : 'bg-gray-700'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              settings.hide_vm_microcode_cves ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
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

function TwoFactorSection() {
  const qc = useQueryClient()
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: api.auth.me })

  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string; qr_code_svg: string } | null>(null)
  const [enableCode, setEnableCode] = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [error, setError] = useState('')

  const startSetup = useMutation({
    mutationFn: () => api.auth.twoFactor.setup(),
    onSuccess: (data) => { setSetup(data); setError('') },
    onError: (e: Error) => setError(e.message),
  })

  const enable = useMutation({
    mutationFn: () => api.auth.twoFactor.enable(enableCode),
    onSuccess: (data) => {
      setBackupCodes(data.backup_codes)
      setSetup(null)
      setEnableCode('')
      setError('')
      qc.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (e: Error) => setError(e.message),
  })

  const disable = useMutation({
    mutationFn: () => api.auth.twoFactor.disable(disableCode),
    onSuccess: () => {
      setDisableCode('')
      setError('')
      qc.invalidateQueries({ queryKey: ['me'] })
    },
    onError: (e: Error) => setError(e.message),
  })

  if (!me) return null

  return (
    <div>
      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">
        Zwei-Faktor-Authentifizierung (2FA)
      </h2>

      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            {me.totp_enabled
              ? <ShieldCheck size={18} className="text-green-400" />
              : <ShieldOff size={18} className="text-gray-500" />}
            <div>
              <div className="text-sm font-medium text-gray-200">
                {me.totp_enabled ? '2FA ist aktiviert' : '2FA ist deaktiviert'}
              </div>
              <div className="text-xs text-gray-500 mt-0.5">
                Schützt deinen Account zusätzlich mit einem Code aus einer
                Authenticator-App (z.B. Google Authenticator, Aegis, 1Password).
              </div>
            </div>
          </div>
          {!me.totp_enabled && !setup && !backupCodes && (
            <button
              onClick={() => startSetup.mutate()}
              disabled={startSetup.isPending}
              className="shrink-0 text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded"
            >
              2FA einrichten
            </button>
          )}
        </div>

        {error && (
          <p className="text-xs text-red-400 bg-red-950 border border-red-800 rounded px-2 py-1">{error}</p>
        )}

        {setup && (
          <div className="border-t border-gray-800 pt-4 space-y-3">
            <p className="text-xs text-gray-400">
              QR-Code mit der Authenticator-App scannen oder das Secret manuell eingeben,
              dann den 6-stelligen Code zur Bestätigung eingeben.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 items-start">
              <div
                className="bg-white p-2 rounded-lg w-40 h-40 shrink-0"
                dangerouslySetInnerHTML={{ __html: setup.qr_code_svg }}
              />
              <div className="space-y-2 flex-1">
                <div>
                  <div className="text-xs text-gray-500 mb-1">Secret (manuelle Eingabe)</div>
                  <code className="text-xs text-indigo-300 break-all">{setup.secret}</code>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1.5">Code aus der App</label>
                  <input
                    className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 font-mono tracking-widest focus:outline-none"
                    placeholder="123456"
                    value={enableCode}
                    onChange={e => setEnableCode(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && enableCode && enable.mutate()}
                  />
                </div>
                <div className="flex gap-2 justify-end">
                  <button onClick={() => { setSetup(null); setError('') }} className="text-xs text-gray-400 hover:text-gray-200 px-3 py-1.5">
                    Abbrechen
                  </button>
                  <button
                    onClick={() => enable.mutate()}
                    disabled={!enableCode || enable.isPending}
                    className="text-xs bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-3 py-1.5 rounded"
                  >
                    Aktivieren
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {backupCodes && (
          <div className="border-t border-gray-800 pt-4 space-y-3">
            <div className="bg-green-950 border-2 border-green-600 rounded-xl p-4">
              <div className="text-green-400 font-bold text-sm mb-2">
                ⚠ Backup-Codes jetzt notieren — werden danach nicht mehr angezeigt!
              </div>
              <p className="text-xs text-gray-400 mb-2">
                Jeder Code kann einmalig verwendet werden, falls die Authenticator-App
                nicht verfügbar ist.
              </p>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm text-green-300">
                {backupCodes.map(c => <div key={c}>{c}</div>)}
              </div>
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => setBackupCodes(null)}
                className="text-xs text-gray-500 hover:text-red-400 border border-gray-700 hover:border-red-700 rounded px-2 py-1 transition-colors"
              >
                Codes notiert — Schließen
              </button>
            </div>
          </div>
        )}

        {me.totp_enabled && !backupCodes && (
          <div className="border-t border-gray-800 pt-4 space-y-2">
            <label className="block text-xs text-gray-400">
              Zum Deaktivieren: aktuellen Code aus der App oder einen Backup-Code eingeben
            </label>
            <div className="flex gap-2">
              <input
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 font-mono tracking-widest focus:outline-none"
                placeholder="123456"
                value={disableCode}
                onChange={e => setDisableCode(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && disableCode && disable.mutate()}
              />
              <button
                onClick={() => disable.mutate()}
                disabled={!disableCode || disable.isPending}
                className="text-xs bg-red-900/50 border border-red-800 hover:bg-red-900 disabled:opacity-40 text-red-300 px-3 py-1.5 rounded whitespace-nowrap"
              >
                2FA deaktivieren
              </button>
            </div>
          </div>
        )}
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
          <GeneralSettingsSection />
        </section>
      )}

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
        <TwoFactorSection />
      </section>

      <section>
        <APIKeySection />
      </section>
    </div>
  )
}
