import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Toaster } from 'sonner'
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
import ReportsAdmin from '@/pages/ReportsAdmin'
import ReportsOperator from '@/pages/ReportsOperator'

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

function ReportsPage() {
  const { user } = useAuth()
  if (!user) return null
  return user.role.name === 'admin' ? <ReportsAdmin /> : <ReportsOperator />
}

export default function App() {
  return (
    <AuthProvider>
      <Toaster position="bottom-right" theme="dark" richColors />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          {/* Rutas accesibles para cualquier rol autenticado */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="audits" element={<Audits />} />
              <Route path="audits/:id" element={<AuditDetail />} />
              <Route path="targets" element={<Targets />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="dashboard" element={<DashboardPage />} />
            </Route>
          </Route>

          {/* Rutas exclusivas de admin */}
          <Route element={<ProtectedRoute requiredRole="admin" />}>
            <Route element={<AppLayout />}>
              {/* <Route path="users" element={<UsersAdmin />} /> */}
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
