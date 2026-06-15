import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Terminal, Clock, User, Server, X, Search } from 'lucide-react'

const token = () => localStorage.getItem('token') ?? ''

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch('/api/v1/sessions' + path, {
    ...opts,
    headers: { Authorization: `Bearer ${token()}`, 'Content-Type': 'application/json', ...opts?.headers },
  })
  if (!res.ok) throw new Error(await res.text())
  if (res.status === 204) return undefined
  return res.json()
}

interface SessionSummary {
  id: string
  session_uuid: string
  operator: string
  jumpbox_host: string | null
  target_host: string
  target_user: string | null
  target_asset_id: string | null
  started_at: string | null
  ended_at: string | null
  duration_sec: number | null
  exit_code: number | null
  has_recording: boolean
  command_count: number
  created_at: string
}

interface Command {
  seq: number
  executed_at: string | null
  command: string
  cwd: string | null
  os_user: string | null
}

interface SessionDetail extends SessionSummary {
  recording_format: string
  recording: string | null
  timing: string | null
  commands: Command[]
}

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r/g
const stripAnsi = (s: string) => s.replace(ANSI, '')

function fmtDur(sec: number | null) {
  if (sec == null) return '—'
  if (sec < 60) return `${sec}s`
  const m = Math.floor(sec / 60), s = sec % 60
  return `${m}m ${s}s`
}
function fmtTime(iso: string | null) {
  return iso ? new Date(iso).toLocaleString() : '—'
}

function SessionModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading } = useQuery<SessionDetail>({
    queryKey: ['session', id],
    queryFn: () => apiFetch(`/${id}`),
  })
  const [tab, setTab] = useState<'commands' | 'recording'>('commands')

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <div className="flex items-center gap-2 text-gray-200">
            <Terminal size={18} className="text-emerald-400" />
            <span className="font-semibold">{data?.target_host ?? '…'}</span>
            {data?.target_user && <span className="text-gray-500 text-sm">({data.target_user})</span>}
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200"><X size={20} /></button>
        </div>

        {isLoading || !data ? (
          <div className="p-8 text-center text-gray-500">Lädt…</div>
        ) : (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 text-sm border-b border-gray-800">
              <Meta icon={User} label="Operator" value={data.operator} />
              <Meta icon={Server} label="Jumpbox" value={data.jumpbox_host ?? '—'} />
              <Meta icon={Clock} label="Start" value={fmtTime(data.started_at)} />
              <Meta icon={Clock} label="Dauer" value={fmtDur(data.duration_sec)} />
            </div>

            <div className="flex gap-1 px-4 pt-3">
              <TabBtn active={tab === 'commands'} onClick={() => setTab('commands')}>
                Kommandos ({data.command_count})
              </TabBtn>
              <TabBtn active={tab === 'recording'} onClick={() => setTab('recording')}>
                Aufzeichnung {data.has_recording ? '' : '(keine)'}
              </TabBtn>
            </div>

            <div className="flex-1 overflow-auto p-4">
              {tab === 'commands' ? (
                data.commands.length === 0 ? (
                  <p className="text-gray-500 text-sm">Keine zielseitigen Kommandos protokolliert.</p>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="text-gray-500 text-left">
                      <tr><th className="pb-2 w-10">#</th><th className="pb-2">Zeit</th><th className="pb-2">Kommando</th></tr>
                    </thead>
                    <tbody className="font-mono">
                      {data.commands.map(c => (
                        <tr key={c.seq} className="border-t border-gray-800 align-top">
                          <td className="py-1 text-gray-600">{c.seq}</td>
                          <td className="py-1 text-gray-500 whitespace-nowrap pr-3">{fmtTime(c.executed_at)}</td>
                          <td className="py-1 text-emerald-300 break-all">
                            {c.cwd && <span className="text-gray-600">{c.cwd}$ </span>}
                            {c.command}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
              ) : (
                <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap bg-black/40 rounded p-3">
                  {data.recording ? stripAnsi(data.recording) : 'Keine Aufzeichnung vorhanden.'}
                </pre>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

const Meta = ({ icon: Icon, label, value }: { icon: any; label: string; value: string }) => (
  <div>
    <div className="flex items-center gap-1 text-gray-500 text-xs"><Icon size={12} />{label}</div>
    <div className="text-gray-200 truncate">{value}</div>
  </div>
)
const TabBtn = ({ active, onClick, children }: { active: boolean; onClick: () => void; children: any }) => (
  <button onClick={onClick}
    className={`px-3 py-1.5 rounded-t text-sm ${active ? 'bg-gray-800 text-gray-100' : 'text-gray-400 hover:text-gray-200'}`}>
    {children}
  </button>
)

export default function Sessions() {
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const { data: sessions = [], isLoading } = useQuery<SessionSummary[]>({
    queryKey: ['sessions'],
    queryFn: () => apiFetch(''),
  })

  const f = filter.trim().toLowerCase()
  const shown = f
    ? sessions.filter(s =>
        s.target_host.toLowerCase().includes(f) || s.operator.toLowerCase().includes(f))
    : sessions

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center gap-2 mb-1">
        <Terminal className="text-emerald-400" />
        <h1 className="text-xl font-semibold text-gray-100">Audit-Sessions</h1>
      </div>
      <p className="text-gray-500 text-sm mb-4">Über die Jumpbox aufgezeichnete SSH-Sessions zu Zielhosts.</p>

      <div className="relative mb-4 max-w-sm">
        <Search size={16} className="absolute left-3 top-2.5 text-gray-500" />
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Zielhost oder Operator…"
          className="w-full pl-9 pr-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-gray-200" />
      </div>

      {isLoading ? (
        <p className="text-gray-500">Lädt…</p>
      ) : shown.length === 0 ? (
        <p className="text-gray-500">Keine Sessions.</p>
      ) : (
        <div className="border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-800/50 text-gray-400 text-left">
              <tr>
                <th className="px-4 py-2">Zielhost</th>
                <th className="px-4 py-2">Operator</th>
                <th className="px-4 py-2">Start</th>
                <th className="px-4 py-2">Dauer</th>
                <th className="px-4 py-2 text-right">Kommandos</th>
              </tr>
            </thead>
            <tbody>
              {shown.map(s => (
                <tr key={s.id} onClick={() => setSelected(s.id)}
                    className="border-t border-gray-800 hover:bg-gray-800/40 cursor-pointer">
                  <td className="px-4 py-2 text-gray-200">{s.target_host}</td>
                  <td className="px-4 py-2 text-gray-400">{s.operator}</td>
                  <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{fmtTime(s.started_at)}</td>
                  <td className="px-4 py-2 text-gray-500">{fmtDur(s.duration_sec)}</td>
                  <td className="px-4 py-2 text-right text-gray-400">
                    {s.command_count}{s.has_recording && <span className="ml-2 text-emerald-500" title="Aufzeichnung vorhanden">●</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <SessionModal id={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
