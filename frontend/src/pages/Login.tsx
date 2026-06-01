import { useState, useEffect, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Lock, Terminal, ShieldCheck, Search,
  Key, Eye, EyeOff, Zap, LogIn,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAuth } from '@/context/AuthContext'

export default function Login() {
  const { login, token } = useAuth()
  const navigate = useNavigate()
  const { t } = useTranslation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  // Si ya hay sesión activa, redirigir directamente
  useEffect(() => {
    if (token) navigate('/audits', { replace: true })
  }, [token, navigate])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
      navigate('/audits', { replace: true })
    } catch {
      setError(t('login.invalidCreds'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen" style={{ background: '#0d1117' }}>

      {/* ── Panel izquierdo ── */}
      <div className="hidden lg:flex flex-col w-2/5 p-12 relative overflow-hidden">

        {/* Iconos de fondo decorativos */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none select-none">
          <Shield   className="absolute top-6  left-10  h-16 w-16 text-white opacity-[0.06]" />
          <Lock     className="absolute top-6  left-36  h-14 w-14 text-white opacity-[0.06]" />
          <Terminal className="absolute top-6  left-60  h-14 w-14 text-white opacity-[0.06]" />
          <ShieldCheck className="absolute top-6  right-6  h-16 w-16 text-white opacity-[0.06]" />
          <Shield   className="absolute top-36 left-6   h-24 w-24 text-white opacity-[0.04]" />
          <Search   className="absolute top-44 left-52  h-20 w-20 text-white opacity-[0.04]" />
          <Key      className="absolute top-48 right-2  h-18 w-18 text-white opacity-[0.04]" />
          <ShieldCheck className="absolute top-64 left-32  h-20 w-20 text-white opacity-[0.04]" />
        </div>

        <div className="relative z-10 flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-16">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-white font-semibold text-xl tracking-tight">AuditFlow</span>
          </div>

          {/* Headline */}
          <div className="flex-1">
            <h1 className="text-4xl font-bold text-white leading-tight mb-4">
              {t('login.tagline')}
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed max-w-xs">
              {t('login.taglineDesc')}
            </p>

            {/* Feature chips */}
            <div className="mt-12 space-y-3">
              <div className="flex items-center gap-3 rounded-lg bg-white/5 px-4 py-3">
                <Zap className="h-4 w-4 shrink-0 text-yellow-400" />
                <span className="text-slate-300 text-sm">{t('login.feature1')}</span>
              </div>
              <div className="flex items-center gap-3 rounded-lg bg-white/5 px-4 py-3">
                <ShieldCheck className="h-4 w-4 shrink-0 text-green-400" />
                <span className="text-slate-300 text-sm">{t('login.feature2')}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Panel derecho ── */}
      <div
        className="flex flex-1 flex-col items-center justify-between p-8"
        style={{ background: '#111827' }}
      >
        <div className="flex w-full max-w-md flex-1 flex-col justify-center">
          {/* Cabecera del form */}
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">{t('login.welcome')}</h2>
            <p className="text-sm text-slate-400">
              {t('login.welcomeDesc')}
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-slate-400">
                {t('login.username')}
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder={t('login.usernamePlaceholder')}
                  required
                  autoComplete="username"
                  className="w-full rounded-lg border border-white/10 bg-white/5 py-3 pl-10 pr-4 text-sm text-white placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-slate-400">
                {t('login.password')}
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-white/10 bg-white/5 py-3 pl-10 pr-10 text-sm text-white placeholder:text-slate-500 focus:border-transparent focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                  tabIndex={-1}
                >
                  {showPassword
                    ? <EyeOff className="h-4 w-4" />
                    : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <p className="text-sm text-red-400">{error}</p>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-blue-500 px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading
                ? <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                : <LogIn className="h-4 w-4" />}
              {t('login.signIn')}
            </button>
          </form>

          <p className="mt-8 text-center text-xs text-slate-500">
            {t('login.contactAdmin')}
          </p>
        </div>

        {/* Footer */}
        <div className="w-full space-y-2 text-center">
          <div className="flex items-center justify-center gap-3 text-xs text-slate-600">
            <span>{t('login.privacy')}</span>
            <span>·</span>
            <span>{t('login.terms')}</span>
            <span>·</span>
            <span>{t('login.security')}</span>
          </div>
          <p className="text-xs text-slate-700">{t('login.copyright')}</p>
        </div>
      </div>

    </div>
  )
}
