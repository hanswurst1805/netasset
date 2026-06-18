import { NavLink, useNavigate } from 'react-router-dom'
import { Server, ShieldAlert, MessageSquare, Workflow, Settings, LogOut, AlertTriangle, Network, Globe, BarChart2, CreditCard, Terminal, Boxes } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { fetchConflictCount } from '../pages/ConflictQueue'

const nav = [
  { to: '/assets',    icon: Server,        label: 'Assets',          group: null },
  { to: '/reporting', icon: BarChart2,     label: 'Reports',         group: null },
  { to: '/cards',     icon: CreditCard,   label: 'Karteikarten',    group: null },
  { to: '/networks',  icon: Globe,         label: 'Netzwerke',       group: null },
  { to: '/topology',  icon: Network,       label: 'Topologie',       group: null },
  { to: '/cve',       icon: ShieldAlert,   label: 'CVE Dashboard',   group: null },
  { to: '/sessions',  icon: Terminal,      label: 'Audit-Sessions',  group: null },
  { to: '/containers', icon: Boxes,         label: 'Container',        group: null },
  { to: '/chat',      icon: MessageSquare, label: 'Chatbot',         group: null },
  { to: '/basis',    icon: Workflow,      label: 'BASIS',           group: 'bia' },
  { to: '/processes', icon: Workflow,      label: 'Business-Prozesse', group: 'bia' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const { data: conflictCount = 0 } = useQuery({
    queryKey: ['conflict-stats'],
    queryFn: fetchConflictCount,
    refetchInterval: 60_000,
  })

  function logout() {
    api.auth.logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-gray-950 text-gray-100">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="px-4 py-5 border-b border-gray-800">
          <span className="text-xl font-black tracking-tight text-white">DRUCKER</span>
          <p className="text-xs text-gray-500 mt-0.5">Infrastructure Intelligence</p>
        </div>
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {/* Normale Nav-Einträge */}
          {nav.filter(n => !n.group).map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}

          {/* Business Impact Analyse Gruppe */}
          <div className="pt-2">
            <div className="px-3 py-1 text-xs font-semibold text-gray-600 uppercase tracking-wider">
              Business Impact Analyse
            </div>
            {nav.filter(n => n.group === 'bia').map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                    isActive
                      ? 'bg-indigo-600 text-white'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
                  }`
                }
              >
                <Icon size={16} />
                {label}
              </NavLink>
            ))}
          </div>
        </nav>
        <div className="p-2 border-t border-gray-800 space-y-1">
          <NavLink
            to="/conflicts"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive ? 'bg-yellow-700 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
              }`
            }
          >
            <AlertTriangle size={16} />
            Konflikte
            {conflictCount > 0 && (
              <span className="ml-auto bg-yellow-600 text-white text-xs font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
                {conflictCount}
              </span>
            )}
          </NavLink>

          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
              }`
            }
          >
            <Settings size={16} /> Einstellungen
          </NavLink>
          <button
            onClick={logout}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
          >
            <LogOut size={16} /> Abmelden
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  )
}
