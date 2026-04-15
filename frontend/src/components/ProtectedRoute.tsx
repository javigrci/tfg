import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '@/context/AuthContext'
import { Loader2 } from 'lucide-react'

interface Props {
  requiredRole?: 'admin' | 'operator'
}

export default function ProtectedRoute({ requiredRole }: Props) {
  const { token, user } = useAuth()

  // Sin token → login
  if (!token) return <Navigate to="/" replace />

  // Token presente pero user todavía cargando → esperar
  if (!user) {
    return (
      <div className="flex items-center justify-center h-screen text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    )
  }

  // Rol requerido y no coincide → redirigir a auditorías
  if (requiredRole && user.role.name !== requiredRole) {
    return <Navigate to="/audits" replace />
  }

  return <Outlet />
}
