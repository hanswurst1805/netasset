import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Assets from './pages/Assets'
import AssetDetail from './pages/AssetDetail'
import CVEDashboard from './pages/CVEDashboard'
import Chatbot from './pages/Chatbot'
import Processes from './pages/Processes'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1 } },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Navigate to="/assets" replace />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/:id" element={<AssetDetail />} />
            <Route path="/cve" element={<CVEDashboard />} />
            <Route path="/chat" element={<Chatbot />} />
            <Route path="/processes" element={<Processes />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
