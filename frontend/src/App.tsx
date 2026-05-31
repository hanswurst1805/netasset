import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Login from './pages/Login'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import CVEDashboard from './pages/CVEDashboard'
import Chatbot from './pages/Chatbot'
import Processes from './pages/Processes'
import UserManagement from './pages/UserManagement'
import ConflictQueue from './pages/ConflictQueue'
import NetworkTopology from './pages/NetworkTopology'
import Networks from './pages/Networks'
import Reporting from './pages/Reporting'
import CardExport from './pages/CardExport'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
})

function RequireAuth({ children }: { children: React.ReactNode }) {
  if (!localStorage.getItem('token')) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/*" element={
            <RequireAuth>
              <Layout>
                <Routes>
                  <Route path="/" element={<Navigate to="/assets" replace />} />
                  <Route path="/assets" element={<Assets />} />
                  <Route path="/assets/:id" element={<AssetDetail />} />
                  <Route path="/cve" element={<CVEDashboard />} />
                  <Route path="/chat" element={<Chatbot />} />
                  <Route path="/processes" element={<Processes />} />
                  <Route path="/settings" element={<UserManagement />} />
                  <Route path="/conflicts" element={<ConflictQueue />} />
                  <Route path="/topology" element={<NetworkTopology />} />
                  <Route path="/networks" element={<Networks />} />
                  <Route path="/reporting" element={<Reporting />} />
                  <Route path="/cards" element={<CardExport />} />
                </Routes>
              </Layout>
            </RequireAuth>
          } />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
