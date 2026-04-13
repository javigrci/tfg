import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import axios from 'axios'
import api from '@/lib/api'

export interface AuthUser {
  id: number
  username: string
  role: { id: number; name: 'admin' | 'operator' }
}

interface AuthContextType {
  token: string | null
  user: AuthUser | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem('token')
  )
  const [user, setUser] = useState<AuthUser | null>(null)

  useEffect(() => {
    if (token) {
      api.get('/auth/me')
        .then(r => setUser(r.data))
        .catch(() => {
          localStorage.removeItem('token')
          setToken(null)
          setUser(null)
        })
    } else {
      setUser(null)
    }
  }, [token])

  async function login(username: string, password: string) {
    const response = await axios.post(
      'http://localhost:8000/api/v1/auth/login',
      { username, password }
    )
    const { access_token } = response.data
    localStorage.setItem('token', access_token)
    setToken(access_token)
  }

  function logout() {
    localStorage.removeItem('token')
    setToken(null)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ token, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
