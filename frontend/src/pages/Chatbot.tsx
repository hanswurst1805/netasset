import { useState, useRef, useEffect } from 'react'
import { api } from '../api/client'
import { Send, Bot, User, Database, Shield } from 'lucide-react'

interface Message {
  role: 'user' | 'assistant'
  text: string
  sources_assets?: string[]
  sources_cves?: string[]
  context_size?: number
}

const EXAMPLES = [
  'Welche Systeme sind von außen erreichbar und haben bekannte Schwachstellen?',
  'Welche Softwareversionen sind auf den Webservern installiert?',
  'Auf welchen Systemen läuft OpenSSL und in welcher Version?',
  'Welche Ports sind auf extern erreichbaren Systemen offen?',
  'Welche Systeme haben das höchste Sicherheitsrisiko?',
]

function Sources({ assets, cves, size }: { assets: string[]; cves: string[]; size: number }) {
  const [open, setOpen] = useState(false)
  if (!assets.length && !cves.length) return null
  return (
    <div className="mt-2 border-t border-gray-700 pt-2">
      <button
        onClick={() => setOpen(!open)}
        className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1.5 transition-colors"
      >
        <Database size={11} />
        {assets.length} Assets · {cves.length} CVEs · {(size / 1000).toFixed(0)}k Zeichen Kontext
        <span className="ml-1">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          {assets.length > 0 && (
            <div>
              <div className="text-xs text-gray-600 mb-1">Assets im Kontext:</div>
              <div className="flex flex-wrap gap-1">
                {assets.map(a => (
                  <span key={a} className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{a}</span>
                ))}
              </div>
            </div>
          )}
          {cves.length > 0 && (
            <div>
              <div className="text-xs text-gray-600 mb-1">CVEs durchsucht:</div>
              <div className="flex flex-wrap gap-1">
                {cves.map(c => (
                  <span key={c} className="text-xs bg-gray-800 text-indigo-400 px-2 py-0.5 rounded font-mono">{c}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function Chatbot() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function send(question: string) {
    if (!question.trim() || loading) return
    setMessages(m => [...m, { role: 'user', text: question }])
    setInput('')
    setLoading(true)
    try {
      const res = await api.cve.query(question)
      setMessages(m => [...m, {
        role: 'assistant',
        text: res.answer,
        sources_assets: (res as any).sources_assets ?? [],
        sources_cves: (res as any).sources_cves ?? [],
        context_size: (res as any).context_size ?? 0,
      }])
    } catch (e: any) {
      setMessages(m => [...m, { role: 'assistant', text: `Fehler: ${e.message}`, sources_assets: [], sources_cves: [] }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full max-w-3xl mx-auto">
      <div className="mb-4">
        <h1 className="text-2xl font-bold">Security Chatbot</h1>
        <p className="text-sm text-gray-500 mt-1">
          Antwortet ausschließlich auf Basis der echten CMDB-Daten — keine Halluzinationen.
        </p>
      </div>

      {/* RAG-Hinweis */}
      <div className="flex items-center gap-2 bg-indigo-950 border border-indigo-800 rounded-lg px-3 py-2 mb-4 text-xs text-indigo-300">
        <Shield size={13} />
        Alle Antworten basieren auf den tatsächlichen Asset-Daten deiner CMDB (Ports, Softwareversionen, Exposure-Level, CVEs).
      </div>

      {/* Chat Area */}
      <div className="flex-1 overflow-auto space-y-4 mb-4 min-h-0">
        {messages.length === 0 && (
          <div className="text-center pt-8">
            <Bot size={40} className="text-gray-700 mx-auto mb-4" />
            <p className="text-gray-500 text-sm mb-5">Stelle eine Frage zu deiner Infrastruktur</p>
            <div className="space-y-2">
              {EXAMPLES.map(ex => (
                <button
                  key={ex}
                  onClick={() => send(ex)}
                  className="block w-full text-left bg-gray-900 border border-gray-800 hover:border-indigo-500 text-gray-400 text-sm px-4 py-2.5 rounded-lg transition-colors"
                >
                  {ex}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'justify-end' : ''}`}>
            {m.role === 'assistant' && (
              <div className="shrink-0 w-7 h-7 bg-indigo-600 rounded-full flex items-center justify-center">
                <Bot size={14} />
              </div>
            )}
            <div className={`max-w-[85%] rounded-lg px-4 py-3 text-sm ${
              m.role === 'user'
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-900 border border-gray-800 text-gray-200'
            }`}>
              <div className="whitespace-pre-wrap">{m.text}</div>
              {m.role === 'assistant' && (
                <Sources
                  assets={m.sources_assets ?? []}
                  cves={m.sources_cves ?? []}
                  size={m.context_size ?? 0}
                />
              )}
            </div>
            {m.role === 'user' && (
              <div className="shrink-0 w-7 h-7 bg-gray-700 rounded-full flex items-center justify-center">
                <User size={14} />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="shrink-0 w-7 h-7 bg-indigo-600 rounded-full flex items-center justify-center">
              <Bot size={14} />
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-xs text-gray-500">
              Lade Asset-Daten und analysiere…
              <div className="flex gap-1 mt-2">
                {[0,1,2].map(i => (
                  <div key={i} className="w-1.5 h-1.5 bg-gray-500 rounded-full animate-bounce"
                    style={{ animationDelay: `${i * 0.15}s` }} />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex gap-2">
        <input
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          placeholder="z.B. Welche Systeme haben Port 22 offen und laufen auf Ubuntu?"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send(input)}
          disabled={loading}
        />
        <button
          onClick={() => send(input)}
          disabled={loading || !input.trim()}
          className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white px-4 py-2.5 rounded-lg transition-colors"
        >
          <Send size={16} />
        </button>
      </div>
    </div>
  )
}
