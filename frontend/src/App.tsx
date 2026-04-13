import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/context/AuthContext'
import ProtectedRoute from '@/components/ProtectedRoute'
import AppLayout from '@/components/layout/AppLayout'
import Login from '@/pages/Login'
import DashboardAdmin from '@/pages/DashboardAdmin'
import DashboardOperator from '@/pages/DashboardOperator'
import Audits from '@/pages/Audits'
import AuditDetail from '@/pages/AuditDetail'
import Targets from '@/pages/Targets'
import FindingsAdmin from '@/pages/FindingsAdmin'
import FindingsOperator from '@/pages/FindingsOperator'
import Reports from '@/pages/Reports'

function DashboardPage() {
  const { user } = useAuth()
  if (!user) return null
  return user.role.name === 'admin' ? <DashboardAdmin /> : <DashboardOperator />
}

function FindingsPage() {
  const { user } = useAuth()
  if (!user) return null
  return user.role.name === 'admin' ? <FindingsAdmin /> : <FindingsOperator />
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="audits" element={<Audits />} />
              <Route path="audits/:id" element={<AuditDetail />} />
              <Route path="targets" element={<Targets />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="reports" element={<Reports />} />
              <Route path="dashboard" element={<DashboardPage />} />
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
