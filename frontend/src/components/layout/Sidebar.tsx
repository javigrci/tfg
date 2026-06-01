import { NavLink, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import {
  LayoutDashboard,
  ClipboardList,
  Crosshair,
  AlertTriangle,
  FileText,
  LogOut,
  Shield,
  Users,
  Sun,
  Moon,
  Activity,
  Globe,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuth } from '@/context/AuthContext'
import { useTheme } from '@/context/ThemeContext'
import api from '@/lib/api'

const navItems = [
  { to: '/dashboard', labelKey: 'nav.dashboard', icon: LayoutDashboard, adminOnly: false },
  { to: '/audits',    labelKey: 'nav.audits',    icon: ClipboardList,   adminOnly: false },
  { to: '/targets',   labelKey: 'nav.targets',   icon: Crosshair,       adminOnly: false },
  { to: '/findings',  labelKey: 'nav.findings',  icon: AlertTriangle,   adminOnly: false },
  { to: '/reports',   labelKey: 'nav.reports',   icon: FileText,        adminOnly: false },
  { to: '/users',     labelKey: 'nav.users',     icon: Users,           adminOnly: true  },
  { to: '/activity',  labelKey: 'nav.activity',  icon: Activity,        adminOnly: true  },
]

export default function Sidebar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const { theme, toggleTheme } = useTheme()
  const { t, i18n } = useTranslation()

  const { data: alerts } = useQuery<{ count: number }>({
    queryKey: ['alert-count'],
    queryFn: () => api.get('/findings/alerts').then(r => r.data),
    refetchInterval: 30_000,
    staleTime:       20_000,
  })

  const alertCount = alerts?.count ?? 0

  function handleLogout() {
    logout()
    navigate('/')
  }

  function handleToggleLanguage() {
    const next = i18n.language === 'en' ? 'es' : 'en'
    i18n.changeLanguage(next)
    localStorage.setItem('i18nextLng', next)
  }

  const isAdmin = user?.role.name === 'admin'

  return (
    <aside className="flex h-screen w-56 flex-col bg-sidebar border-r border-sidebar-border">
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary">
          <Shield className="h-4 w-4 text-primary-foreground" />
        </div>
        <span className="text-sm font-semibold tracking-wide text-sidebar-foreground">
          AuditFlow
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 px-3 py-2">
        {navItems
          .filter(({ adminOnly }) => !adminOnly || isAdmin)
          .map(({ to, labelKey, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                isActive
                  ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className="flex-1">{t(labelKey)}</span>
            {to === '/findings' && alertCount > 0 && (
              <span className="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500 px-1.5 text-[10px] font-bold text-white leading-none">
                {alertCount > 99 ? '99+' : alertCount}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User info + controls */}
      <div className="border-t border-sidebar-border px-3 py-3 space-y-1">
        {user && (
          <div className="flex items-center gap-2.5 px-3 py-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground uppercase shrink-0">
              {user.username.slice(0, 1)}
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-sidebar-foreground truncate">{user.username}</p>
              <p className="text-xs text-sidebar-foreground/50 capitalize">{user.role.name}</p>
            </div>
          </div>
        )}
        <button
          onClick={handleToggleLanguage}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground transition-colors"
          title={t('sidebar.switchLanguage')}
        >
          <Globe className="h-4 w-4 shrink-0" />
          {t('sidebar.switchLanguage')}
        </button>
        <button
          onClick={toggleTheme}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground transition-colors"
          title={theme === 'dark' ? t('sidebar.lightMode') : t('sidebar.darkMode')}
        >
          {theme === 'dark'
            ? <Sun  className="h-4 w-4 shrink-0" />
            : <Moon className="h-4 w-4 shrink-0" />
          }
          {theme === 'dark' ? t('sidebar.lightMode') : t('sidebar.darkMode')}
        </button>
        <button
          onClick={handleLogout}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground transition-colors"
        >
          <LogOut className="h-4 w-4 shrink-0" />
          {t('sidebar.logout')}
        </button>
      </div>
    </aside>
  )
}
