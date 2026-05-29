import { useState, useRef, useEffect } from 'react'
import { api } from '../api/client'
import { Send, Bot, User } from 'lucide-react'

interface Message {
  role: 'user' | 'assistant'
  text: string
}

const EXAMPLES = [
  'Welche extern erreichbaren Systeme haben kritische OpenSSL-Lücken?',
  'Welche Assets sind am stärksten gefährdet?',
  'Gibt es bekannte RCE-Schwachstellen in meiner Infrastruktur?',
]

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
      setMessages(m => [...m, { role: 'assistant', text: res.answer }])
    } catch (e: any) {
      setMessages(m => [...m, { role: 'assistant', text: `Fehler: ${e.message}` }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold mb-2">Security Chatbot</h1>
      <p className="text-sm text-gray-500 mb-6">RAG-basierte Freitextanalyse über CVEs und Assets</p>

      {/* Chat Area */}
      <div className="flex-1 overflow-auto space-y-4 mb-4 min-h-0">
        {messages.length === 0 && (
          <div className="text-center pt-12">
            <Bot size={40} className="text-gray-700 mx-auto mb-4" />
            <p className="text-gray-500 text-sm mb-6">Stelle eine Frage zu deiner Infrastruktur</p>
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
            <div className={`max-w-[85%] rounded-lg px-4 py-3 text-sm whitespace-pre-wrap ${
              m.role === 'user'
                ? 'bg-indigo-600 text-white'
                : 'bg-gray-900 border border-gray-800 text-gray-200'
            }`}>
              {m.text}
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
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
              <div className="flex gap-1">
                {[0, 1, 2].map(i => (
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
          placeholder="Frage stellen…"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send(input)}
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
