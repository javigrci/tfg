import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from '@/context/AuthContext'
import ProtectedRoute from '@/components/ProtectedRoute'
import AppLayout from '@/components/layout/AppLayout'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Audits from '@/pages/Audits'
import AuditDetail from '@/pages/AuditDetail'
import Targets from '@/pages/Targets'
import Findings from '@/pages/Findings'
import Reports from '@/pages/Reports'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route index element={<Dashboard />} />
              <Route path="audits" element={<Audits />} />
              <Route path="audits/:id" element={<AuditDetail />} />
              <Route path="targets" element={<Targets />} />
              <Route path="findings" element={<Findings />} />
              <Route path="reports" element={<Reports />} />
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
