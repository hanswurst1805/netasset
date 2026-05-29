import { NavLink } from 'react-router-dom'
import { Server, ShieldAlert, MessageSquare, Workflow } from 'lucide-react'

const nav = [
  { to: '/assets',    icon: Server,        label: 'Assets' },
  { to: '/cve',       icon: ShieldAlert,   label: 'CVE Dashboard' },
  { to: '/chat',      icon: MessageSquare, label: 'Chatbot' },
  { to: '/processes', icon: Workflow,       label: 'Prozesse' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-gray-950 text-gray-100">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <div className="px-4 py-5 border-b border-gray-800">
          <span className="text-lg font-bold text-indigo-400">NetAsset</span>
          <p className="text-xs text-gray-500 mt-0.5">CMDB & Security</p>
        </div>
        <nav className="flex-1 p-2 space-y-1">
          {nav.map(({ to, icon: Icon, label }) => (
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
        </nav>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  )
}
