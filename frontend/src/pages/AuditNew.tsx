import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import {
  ArrowLeft,
  Network,
  Globe,
  Zap,
  Shield,
  ChevronDown,
  Check,
  Info,
} from 'lucide-react'
import api from '@/lib/api'
import type { Target, AuditType, ScanTool } from '@/types'
import { useTranslation } from 'react-i18next'
import { ensureNmap, orderModules, isWebTool } from '@/lib/auditPlan'
import { ExecutionGraph } from '@/components/ExecutionGraph'
import type { ChainGraphResponse } from '@/lib/chainGraph'

const SELECTABLE_TOOLS: ScanTool[] = ['nmap', 'nikto', 'nuclei', 'wapiti']

const TOOL_META: Record<Exclude<ScanTool, 'manual'>, {
  label: string
  icon: React.ReactNode
  color: string
  scope: 'NET' | 'WEB'
}> = {
  nmap:   { label: 'Nmap',   icon: <Network className="h-4 w-4" />, color: '#3b82f6', scope: 'NET' },
  nikto:  { label: 'Nikto',  icon: <Globe   className="h-4 w-4" />, color: '#f59e0b', scope: 'WEB' },
  nuclei: { label: 'Nuclei', icon: <Zap     className="h-4 w-4" />, color: '#8b5cf6', scope: 'WEB' },
  wapiti: { label: 'Wapiti', icon: <Shield  className="h-4 w-4" />, color: '#ef4444', scope: 'WEB' },
}

const AUDIT_TYPES: AuditType[] = ['vulnerability_scan', 'penetration_test', 'compliance']

// Punto de partida por tipo, ajustable. Todos incluyen Nmap para no dejar una
// selección que `ensureNmap` modificaría acto seguido.
const PRESETS: Record<AuditType, ScanTool[]> = {
  vulnerability_scan: ['nmap', 'nikto', 'nuclei', 'wapiti'],
  penetration_test:   ['nmap', 'nuclei', 'wapiti'],
  compliance:         ['nmap', 'nikto', 'nuclei'],
}

export default function AuditNew() {
  const navigate = useNavigate()
  const { t } = useTranslation()

  const [name,        setName]        = useState('')
  const [description, setDescription] = useState('')
  const [targetId,    setTargetId]    = useState('')
  const [auditType,   setAuditType]   = useState<AuditType>('vulnerability_scan')

  const [selected,    setSelected]    = useState<Set<ScanTool>>(new Set())
  // Nmap marcado por el usuario, no por `ensureNmap`
  const [nmapExplicit, setNmapExplicit] = useState(false)

  const hasWebTool = useMemo(() => [...selected].some(isWebTool), [selected])
  const nmapAuto   = selected.has('nmap') && hasWebTool && !nmapExplicit

  const orderedModules = useMemo(() => orderModules([...selected]), [selected])

  const { data: chainGraph } = useQuery<ChainGraphResponse>({
    queryKey: ['chain-graph', orderedModules],
    queryFn: () =>
      api.get(`/tools/chain-graph?modules=${orderedModules.join(',')}`).then(r => r.data),
    enabled: orderedModules.length > 0,
  })

  const { data: targets = [] } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn:  () => api.get('/targets').then(r => r.data),
  })

  const createMutation = useMutation({
    mutationFn: (payload: object) => api.post('/audits', payload),
    onSuccess:  (res) => { toast.success(t('auditNew.toasts.created')); navigate(`/audits/${res.data.id}`) },
    onError:    ()    => toast.error(t('auditNew.toasts.createFailed')),
  })

  function toggleTool(tool: ScanTool) {
    const isRemoving = selected.has(tool)

    // Nmap queda bloqueado mientras haya herramientas web
    if (isRemoving && tool === 'nmap' && hasWebTool) return

    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(tool)) next.delete(tool)
      else next.add(tool)
      return ensureNmap(next)
    })

    if (tool === 'nmap') setNmapExplicit(!isRemoving)
  }

  function applyPreset(type: AuditType) {
    setAuditType(type)
    setSelected(ensureNmap(new Set(PRESETS[type])))
    setNmapExplicit(PRESETS[type].includes('nmap'))
  }

  const canCreate =
    !!name.trim() && !!targetId && selected.size > 0 && !createMutation.isPending

  function handleCreate() {
    if (!name.trim())     return toast.error(t('auditNew.toasts.nameRequired'))
    if (!targetId)        return toast.error(t('auditNew.toasts.targetRequired'))
    if (selected.size === 0) return toast.error(t('auditNew.toasts.toolRequired'))

    createMutation.mutate({
      name:        name.trim(),
      description: description.trim() || null,
      audit_type:  auditType,
      target_id:   parseInt(targetId),
      modules:     orderModules([...selected]),
    })
  }

  return (
    <div className="flex h-full flex-col -m-8">

      {/* Header */}
      <div className="flex shrink-0 items-center gap-3 border-b border-border bg-background px-6 py-4">
        <button
          onClick={() => navigate('/audits')}
          className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          {t('common.backToAudits')}
        </button>
        <span className="text-muted-foreground/30">/</span>
        <h1 className="text-sm font-semibold text-foreground">{t('auditNew.title')}</h1>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-2xl flex-col gap-8 p-8">

          <section className="flex flex-col gap-4">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('auditNew.auditDetails')}
            </p>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-foreground">
                {t('auditNew.nameLabel')} <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder={t('auditNew.namePlaceholder')}
                className="rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-medium text-foreground">{t('auditNew.descriptionLabel')}</label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                rows={2}
                placeholder={t('auditNew.descPlaceholder')}
                className="resize-none rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-foreground">
                  {t('auditNew.targetLabel')} <span className="text-destructive">*</span>
                </label>
                <div className="relative">
                  <select
                    value={targetId}
                    onChange={e => setTargetId(e.target.value)}
                    className="w-full appearance-none rounded-md border border-input bg-background px-3 py-2 pr-8 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  >
                    <option value="">{t('auditNew.selectTarget')}</option>
                    {targets.map(tgt => (
                      <option key={tgt.id} value={tgt.id}>{tgt.name} — {tgt.address}</option>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-foreground">{t('auditNew.auditTypeLabel')}</label>
                <div className="relative">
                  <select
                    value={auditType}
                    onChange={e => setAuditType(e.target.value as AuditType)}
                    className="w-full appearance-none rounded-md border border-input bg-background px-3 py-2 pr-8 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  >
                    {AUDIT_TYPES.map(type => (
                      <option key={type} value={type}>{t(`auditNew.auditTypes.${type}.label`)}</option>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            </div>
          </section>

          <section className="flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('auditNew.presetsLabel')}
            </p>
            <div className="flex flex-wrap gap-2">
              {AUDIT_TYPES.map(type => (
                <button
                  key={type}
                  type="button"
                  onClick={() => applyPreset(type)}
                  className="rounded-md border border-input bg-background px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-muted"
                >
                  {t(`auditNew.auditTypes.${type}.label`)}
                </button>
              ))}
            </div>
          </section>

          <section className="flex flex-col gap-3">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('auditNew.availableTools')} <span className="text-destructive">*</span>
            </p>
            <p className="text-xs text-muted-foreground/70">{t('auditNew.toolsHint')}</p>

            <div className="grid grid-cols-2 gap-3">
              {SELECTABLE_TOOLS.map(tool => {
                const meta       = TOOL_META[tool as Exclude<ScanTool, 'manual'>]
                const isSelected = selected.has(tool)
                return (
                  <button
                    key={tool}
                    type="button"
                    onClick={() => toggleTool(tool)}
                    aria-pressed={isSelected}
                    className="flex flex-col gap-2 rounded-lg border p-3.5 text-left transition-all hover:shadow-sm"
                    style={{
                      borderColor: isSelected ? meta.color : 'rgba(255,255,255,0.10)',
                      background:  isSelected ? meta.color + '11' : 'transparent',
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md"
                        style={{ backgroundColor: meta.color + '22', color: meta.color }}
                      >
                        {meta.icon}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-semibold text-foreground">{meta.label}</p>
                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${
                            meta.scope === 'NET'
                              ? 'bg-blue-500/20 text-blue-400'
                              : 'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {t(`auditNew.toolScope.${meta.scope}`)}
                          </span>
                        </div>
                        <p className="truncate text-xs text-muted-foreground">{t(`auditNew.tools.${tool}.desc`)}</p>
                      </div>
                      <div
                        className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors"
                        style={{
                          borderColor: isSelected ? meta.color : 'rgba(255,255,255,0.20)',
                          background:  isSelected ? meta.color : 'transparent',
                        }}
                      >
                        {isSelected && <Check className="h-3 w-3 text-white" />}
                      </div>
                    </div>

                    {tool === 'nmap' && nmapAuto && (
                      <div className="flex items-start gap-1.5 rounded-md bg-blue-500/10 px-2 py-1.5 text-[11px] leading-snug text-blue-300">
                        <Info className="mt-0.5 h-3 w-3 shrink-0" />
                        <span>{t('auditNew.nmapAutoHint')}</span>
                      </div>
                    )}
                  </button>
                )
              })}
            </div>
          </section>

          {chainGraph && orderedModules.length > 0 && (
            <section className="flex flex-col gap-3 rounded-lg border border-border bg-muted/20 p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {t('auditNew.graph.title')}
              </p>
              <ExecutionGraph graph={chainGraph} />
            </section>
          )}

          <button
            onClick={handleCreate}
            disabled={!canCreate}
            className="rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {createMutation.isPending ? t('auditNew.creating') : t('auditNew.createAudit')}
          </button>
        </div>
      </div>
    </div>
  )
}
