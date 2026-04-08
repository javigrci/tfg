import { createContext, useContext, useState, type ReactNode } from 'react'
import axios from 'axios'

interface AuthContextType {
  token: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem('token')
  )

  async function login(username: string, password: string) {
    const params = new URLSearchParams()
    params.append('username', username)
    params.append('password', password)

    const response = await axios.post(
      'http://localhost:8000/api/v1/auth/login',
      params,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    )

    const { access_token } = response.data
    localStorage.setItem('token', access_token)
    setToken(access_token)
  }

  function logout() {
    localStorage.removeItem('token')
    setToken(null)
  }

  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
