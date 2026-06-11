import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { ShieldAlert, KeyRound } from 'lucide-react'

export default function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const result = await api.auth.login(username, password)
      if (result.mfa_required && result.mfa_token) {
        setMfaToken(result.mfa_token)
      } else {
        navigate('/assets')
      }
    } catch {
      setError('Benutzername oder Passwort falsch')
    } finally {
      setLoading(false)
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    if (!mfaToken) return
    setError('')
    setLoading(true)
    try {
      await api.auth.verify2FA(mfaToken, code)
      navigate('/assets')
    } catch {
      setError('Code ungültig')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-indigo-600 rounded-2xl mb-4">
            <ShieldAlert size={28} />
          </div>
          <h1 className="text-3xl font-black tracking-tight text-white">DRUCKER</h1>
          <p className="text-gray-500 text-sm mt-1">Infrastructure Intelligence</p>
        </div>

        {!mfaToken && (
          <form onSubmit={submit} className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Benutzername</label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={username}
                onChange={e => setUsername(e.target.value)}
                autoFocus
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">Passwort</label>
              <input
                type="password"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>

            {error && (
              <p className="text-sm text-red-400 bg-red-950 border border-red-800 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading || !username || !password}
              className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-sm font-medium py-2 rounded-lg transition-colors"
            >
              {loading ? 'Anmelden…' : 'Anmelden'}
            </button>
          </form>
        )}

        {mfaToken && (
          <form onSubmit={submitCode} className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-gray-300">
              <KeyRound size={16} />
              <span className="text-sm font-medium">Zwei-Faktor-Authentifizierung</span>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1.5">
                Code aus der Authenticator-App oder Backup-Code
              </label>
              <input
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono tracking-widest"
                value={code}
                onChange={e => setCode(e.target.value)}
                placeholder="123456"
                autoFocus
              />
            </div>

            {error && (
              <p className="text-sm text-red-400 bg-red-950 border border-red-800 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading || !code}
              className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white text-sm font-medium py-2 rounded-lg transition-colors"
            >
              {loading ? 'Prüfe…' : 'Bestätigen'}
            </button>
            <button
              type="button"
              onClick={() => { setMfaToken(null); setCode(''); setError('') }}
              className="w-full text-xs text-gray-500 hover:text-gray-300"
            >
              Zurück zum Login
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
