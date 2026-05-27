import { useState, useCallback, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  ReactFlow,
  Background,
  Controls,
  addEdge,
  useNodesState,
  useEdgesState,
  Handle,
  Position,
  type Node,
  type Edge,
  type Connection,
  type NodeProps,
  type NodeTypes,
  BackgroundVariant,
  MarkerType,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { toast } from 'sonner'
import {
  ArrowLeft,
  Network,
  Globe,
  Zap,
  Shield,
  ShieldCheck,
  Lock,
  ClipboardCheck,
  ChevronDown,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Wand2,
} from 'lucide-react'
import api from '@/lib/api'
import type { Target, AuditType, ScanTool } from '@/types'
import { useTheme } from '@/context/ThemeContext'

// ── Types ─────────────────────────────────────────────────────────────────────

type WorkflowType = AuditType | 'custom'

interface WorkflowWarning {
  id: string
  severity: 'error' | 'warning'
  message: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const TOOL_META: Record<ScanTool, {
  label: string; desc: string
  icon: React.ReactNode; color: string; tags: string[]
  scope: 'NET' | 'WEB'
}> = {
  nmap:   { label: 'Nmap',   desc: 'Port & service discovery',   icon: <Network className="h-4 w-4" />, color: '#3b82f6', tags: ['network', 'ports'],    scope: 'NET' },
  nikto:  { label: 'Nikto',  desc: 'Web server vulnerabilities', icon: <Globe   className="h-4 w-4" />, color: '#f59e0b', tags: ['web', 'headers'],       scope: 'WEB' },
  nuclei: { label: 'Nuclei', desc: 'CVE template scanning',      icon: <Zap     className="h-4 w-4" />, color: '#8b5cf6', tags: ['cve', 'template'],      scope: 'WEB' },
  wapiti: { label: 'Wapiti', desc: 'Web app SQLi / XSS / LFI',  icon: <Shield  className="h-4 w-4" />, color: '#ef4444', tags: ['injection', 'web'],     scope: 'WEB' },
}

const AUDIT_TYPE_META: Record<AuditType, { label: string; description: string; icon: React.ReactNode }> = {
  vulnerability_scan: { label: 'Vulnerability Scan', description: 'Broad coverage across network and web layers', icon: <ShieldCheck    className="h-4 w-4" /> },
  penetration_test:   { label: 'Penetration Test',   description: 'Active exploitation-oriented scanning',        icon: <Lock          className="h-4 w-4" /> },
  compliance:         { label: 'Compliance Audit',   description: 'Security headers and policy verification',     icon: <ClipboardCheck className="h-4 w-4" /> },
}

const DEFAULT_WORKFLOWS: Record<AuditType, ScanTool[]> = {
  vulnerability_scan: ['nmap', 'nikto', 'nuclei', 'wapiti'],
  penetration_test:   ['nmap', 'nuclei', 'wapiti'],
  compliance:         ['nikto', 'nuclei'],
}

const EDGE_DEFAULTS = {
  animated: true,
  style:    { stroke: '#4b5563', strokeWidth: 2 },
  markerEnd: { type: MarkerType.ArrowClosed, color: '#4b5563' },
  deletable: true,
}

const HANDLE_STYLE: React.CSSProperties = {
  width: 10, height: 10,
  background: '#374151',
  border: '2px solid #6b7280',
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function buildNextMap(edges: Edge[]): Record<string, string[]> {
  const map: Record<string, string[]> = {}
  for (const e of edges) {
    if (!map[e.source]) map[e.source] = []
    map[e.source].push(e.target)
  }
  return map
}

/** Traverses from 'start' following the first outgoing edge of each node. */
function getExecutionOrder(nodes: Node[], edges: Edge[]): ScanTool[] {
  const nextMap = buildNextMap(edges)
  const order: ScanTool[] = []
  let current = 'start'
  const visited = new Set<string>(['start'])

  while (nextMap[current]?.[0]) {
    const next = nextMap[current][0]
    if (visited.has(next)) break
    visited.add(next)
    if (next === 'end') break
    const node = nodes.find(n => n.id === next)
    if (node?.type === 'toolNode') {
      order.push((node.data as Record<string, unknown>).tool as ScanTool)
    }
    current = next
  }
  return order
}

function detectWorkflowType(order: ScanTool[]): WorkflowType {
  for (const [type, preset] of Object.entries(DEFAULT_WORKFLOWS) as [AuditType, ScanTool[]][]) {
    if (JSON.stringify(order) === JSON.stringify(preset)) return type
  }
  return 'custom'
}

function analyzeWorkflow(nodes: Node[], edges: Edge[], order: ScanTool[]): WorkflowWarning[] {
  const warnings: WorkflowWarning[] = []

  if (order.length === 0) {
    warnings.push({ id: 'empty', severity: 'error', message: 'Add at least one tool to the workflow.' })
    return warnings
  }

  // Disconnected tool nodes
  const reachable = new Set<string>()
  const nextMap = buildNextMap(edges)
  let cur = 'start'
  const vis = new Set<string>()
  while (nextMap[cur]?.[0] && !vis.has(cur)) {
    vis.add(cur); reachable.add(cur); cur = nextMap[cur][0]
  }
  reachable.add(cur)

  const disconnected = nodes.filter(n => n.type === 'toolNode' && !reachable.has(n.id))
  if (disconnected.length > 0) {
    const names = disconnected.map(n => TOOL_META[(n.data as Record<string, unknown>).tool as ScanTool].label).join(', ')
    warnings.push({
      id: 'disconnected', severity: 'error',
      message: `${names} ${disconnected.length === 1 ? 'is' : 'are'} not connected to the execution chain.`,
    })
  }

  // Branching (multiple outgoing edges)
  const outCount: Record<string, number> = {}
  for (const e of edges) outCount[e.source] = (outCount[e.source] ?? 0) + 1
  if (Object.values(outCount).some(c => c > 1)) {
    warnings.push({
      id: 'branching', severity: 'warning',
      message: 'Branching detected: only the first outgoing connection per node will be executed.',
    })
  }

  // Web tools without Nmap
  const hasNmap = order.includes('nmap')
  const webTools = (['nikto', 'wapiti'] as ScanTool[]).filter(t => order.includes(t))
  if (webTools.length > 0 && !hasNmap) {
    warnings.push({
      id: 'web-no-nmap', severity: 'warning',
      message: `${webTools.map(t => TOOL_META[t].label).join(' and ')} benefit from Nmap running first to identify open web ports.`,
    })
  }

  // Nmap after web tools
  if (hasNmap && webTools.length > 0) {
    const nmapIdx    = order.indexOf('nmap')
    const firstWeb   = Math.min(...webTools.map(t => order.indexOf(t)))
    if (nmapIdx > firstWeb) {
      warnings.push({
        id: 'nmap-late', severity: 'warning',
        message: 'Nmap is placed after web tools. Move it earlier for better port discovery.',
      })
    }
  }

  return warnings
}

/** Builds a fresh linear node/edge graph from an ordered tool array. */
function buildGraph(
  tools: ScanTool[],
  onRemove: (id: string) => void,
): { nodes: Node[]; edges: Edge[] } {
  const GAP = 165
  const nodes: Node[] = [
    { id: 'start', type: 'startNode', position: { x: 0, y: 0 },            data: {}, draggable: false, deletable: false },
  ]
  tools.forEach((tool, i) => {
    const id = `tool-${i}-${tool}`
    nodes.push({
      id, type: 'toolNode',
      position: { x: -120, y: GAP * (i + 1) },
      data: { tool, onRemove, nodeId: id },
      deletable: false,
    })
  })
  nodes.push({
    id: 'end', type: 'endNode',
    position: { x: 0, y: GAP * (tools.length + 1) },
    data: {}, draggable: false, deletable: false,
  })

  const ids    = ['start', ...tools.map((t, i) => `tool-${i}-${t}`), 'end']
  const edges: Edge[] = ids.slice(0, -1).map((src, i) => ({
    id: `e-${i}`, source: src, target: ids[i + 1], ...EDGE_DEFAULTS,
  }))
  return { nodes, edges }
}

// ── Custom node components ────────────────────────────────────────────────────

function StartNode(_: NodeProps) {
  return (
    <div className="flex items-center gap-2 rounded-full border border-green-500/40 bg-green-500/10 px-4 py-2 text-xs font-semibold text-green-400">
      <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
      Target
      <Handle type="source" position={Position.Bottom} style={HANDLE_STYLE} />
    </div>
  )
}

function EndNode(_: NodeProps) {
  return (
    <div className="flex items-center gap-2 rounded-full border border-border bg-muted/30 px-4 py-2 text-xs font-semibold text-muted-foreground">
      <Handle type="target" position={Position.Top} style={HANDLE_STYLE} />
      <div className="h-2 w-2 rounded-full bg-muted-foreground/40" />
      Report
    </div>
  )
}

function ToolNode({ data, id }: NodeProps) {
  const tool     = (data as Record<string, unknown>).tool as ScanTool
  const onRemove = (data as Record<string, unknown>).onRemove as (id: string) => void
  const meta     = TOOL_META[tool]
  return (
    <div
      className="relative w-60 rounded-lg bg-card shadow-md"
      style={{
        borderTop:    '1px solid rgba(255,255,255,0.08)',
        borderRight:  '1px solid rgba(255,255,255,0.08)',
        borderBottom: '1px solid rgba(255,255,255,0.08)',
        borderLeft:   `3px solid ${meta.color}`,
      }}
    >
      <Handle type="target" position={Position.Top}    style={HANDLE_STYLE} />
      <div className="flex items-center gap-3 p-4">
        <div
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md"
          style={{ backgroundColor: meta.color + '22', color: meta.color }}
        >
          {meta.icon}
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground">{meta.label}</p>
          <p className="truncate text-sm text-muted-foreground">{meta.desc}</p>
        </div>
        <button
          onClick={e => { e.stopPropagation(); onRemove(id) }}
          className="nodrag flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-destructive/80 text-destructive-foreground text-xs hover:bg-destructive transition-colors"
          title="Remove from workflow"
        >
          ✕
        </button>
      </div>
      <div className="flex gap-1.5 px-4 pb-3">
        {meta.tags.map(tag => (
          <span
            key={tag}
            className="rounded px-2 py-0.5 text-xs font-medium"
            style={{ backgroundColor: meta.color + '22', color: meta.color }}
          >
            {tag}
          </span>
        ))}
      </div>
      <Handle type="source" position={Position.Bottom} style={HANDLE_STYLE} />
    </div>
  )
}

const NODE_TYPES: NodeTypes = {
  startNode: StartNode as NodeTypes[string],
  endNode:   EndNode   as NodeTypes[string],
  toolNode:  ToolNode  as NodeTypes[string],
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AuditNew() {
  const navigate    = useNavigate()
  const { theme }   = useTheme()

  const [name,        setName]        = useState('')
  const [description, setDescription] = useState('')
  const [targetId,    setTargetId]    = useState('')
  const [auditType,   setAuditType]   = useState<AuditType>('vulnerability_scan')

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  // Derived
  const executionOrder = useMemo(() => getExecutionOrder(nodes, edges), [nodes, edges])
  const detectedType   = useMemo(() => detectWorkflowType(executionOrder), [executionOrder])
  const warnings       = useMemo(() => analyzeWorkflow(nodes, edges, executionOrder), [nodes, edges, executionOrder])

  // Remove a tool node and heal the edges around it
  const handleRemoveTool = useCallback((nodeId: string) => {
    setEdges(prev => {
      const inEdge  = prev.find(e => e.target === nodeId)
      const outEdge = prev.find(e => e.source === nodeId)
      const rest    = prev.filter(e => e.source !== nodeId && e.target !== nodeId)
      if (inEdge && outEdge) {
        return [...rest, {
          id: `e-${inEdge.source}-${outEdge.target}`,
          source: inEdge.source,
          target: outEdge.target,
          ...EDGE_DEFAULTS,
        }]
      }
      return rest
    })
    setNodes(prev => prev.filter(n => n.id !== nodeId))
  }, [setNodes, setEdges])

  // Initialise canvas on mount — empty by default
  useEffect(() => {
    const { nodes: n, edges: e } = buildGraph([], handleRemoveTool)
    setNodes(n)
    setEdges(e)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Add tool from palette → append before 'end'
  function addTool(tool: ScanTool) {
    if (executionOrder.includes(tool)) {
      toast.warning(`${TOOL_META[tool].label} is already in the workflow`)
      return
    }
    const newId = `tool-${Date.now()}-${tool}`

    setNodes(prev => {
      const endNode = prev.find(n => n.id === 'end')!
      const updated = prev.map(n =>
        n.id === 'end' ? { ...n, position: { ...n.position, y: n.position.y + 165 } } : n
      )
      return [...updated, {
        id: newId, type: 'toolNode',
        position: { x: -120, y: endNode.position.y },
        data: { tool, onRemove: handleRemoveTool, nodeId: newId },
        deletable: false,
      }]
    })

    setEdges(prev => {
      const toEnd    = prev.find(e => e.target === 'end')
      const rest     = prev.filter(e => e.target !== 'end')
      const pred     = toEnd?.source ?? 'start'
      return [
        ...rest,
        { id: `e-${pred}-${newId}`,  source: pred,  target: newId,  ...EDGE_DEFAULTS },
        { id: `e-${newId}-end`,      source: newId, target: 'end',  ...EDGE_DEFAULTS },
      ]
    })
  }

  // Select a preset → confirm if custom, then reset canvas
  function handleTypeChange(type: AuditType) {
    if (
      detectedType === 'custom' &&
      !window.confirm(`Reset workflow to "${AUDIT_TYPE_META[type].label}" defaults?\nYour custom workflow will be replaced.`)
    ) return

    setAuditType(type)
    const { nodes: n, edges: e } = buildGraph(DEFAULT_WORKFLOWS[type], handleRemoveTool)
    setNodes(n)
    setEdges(e)
  }

  const onConnect = useCallback(
    (connection: Connection) =>
      setEdges(eds => addEdge<Edge>({ ...connection, ...EDGE_DEFAULTS }, eds)),
    [setEdges],
  )

  const { data: targets = [] } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn:  () => api.get('/targets').then(r => r.data),
  })

  const createMutation = useMutation({
    mutationFn: (payload: object) => api.post('/audits', payload),
    onSuccess:  (res) => { toast.success('Audit created'); navigate(`/audits/${res.data.id}`) },
    onError:    ()    => toast.error('Failed to create audit'),
  })

  function handleCreate() {
    if (!name.trim())                return toast.error('Audit name is required')
    if (!targetId)                   return toast.error('Please select a target')
    if (executionOrder.length === 0) return toast.error('Add at least one tool to the workflow')
    if (warnings.some(w => w.severity === 'error')) return toast.error('Fix errors in the workflow before creating')

    createMutation.mutate({
      name:        name.trim(),
      description: description.trim() || null,
      audit_type:  auditType,
      target_id:   parseInt(targetId),
      modules:     executionOrder,
    })
  }

  const hasErrors = warnings.some(w => w.severity === 'error')
  const canCreate = !!name.trim() && !!targetId && executionOrder.length > 0 && !hasErrors && !createMutation.isPending

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex h-full flex-col -m-8">

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div className="flex shrink-0 items-center gap-3 border-b border-border bg-background px-6 py-4">
        <button
          onClick={() => navigate('/audits')}
          className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Audits
        </button>
        <span className="text-muted-foreground/30">/</span>
        <h1 className="text-sm font-semibold text-foreground">New Audit</h1>
      </div>

      {/* ── Body ──────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left — Tool palette + Warnings */}
        <div className="flex w-72 shrink-0 flex-col border-r border-border bg-card/50 overflow-y-auto">
          <div className="flex flex-col gap-2.5 p-5">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Available Tools
            </p>
            <p className="text-xs leading-relaxed text-muted-foreground/60">
              Click to add to the workflow.
            </p>

            {(['nmap', 'nikto', 'nuclei', 'wapiti'] as ScanTool[]).map(tool => {
              const meta  = TOOL_META[tool]
              const added = executionOrder.includes(tool)
              return (
                <button
                  key={tool}
                  onClick={() => addTool(tool)}
                  disabled={added}
                  className="flex items-center gap-3 rounded-lg border p-3.5 text-left transition-all hover:shadow-md disabled:cursor-not-allowed disabled:opacity-40"
                  style={{
                    borderColor: meta.color + '55',
                    background:  added ? meta.color + '11' : 'transparent',
                  }}
                >
                  <div
                    className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md"
                    style={{ backgroundColor: meta.color + '22', color: meta.color }}
                  >
                    {meta.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-foreground">{meta.label}</p>
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wider ${
                        meta.scope === 'NET'
                          ? 'bg-blue-500/20 text-blue-400'
                          : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {meta.scope}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{meta.desc}</p>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Workflow alerts */}
          <div className="mt-auto flex flex-col gap-2 p-5 pt-0">
            {warnings.length === 0 && executionOrder.length > 0 && (
              <div className="flex items-center gap-2 rounded-md border border-green-500/30 bg-green-500/10 p-3">
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-green-400" />
                <p className="text-[11px] text-green-300 font-medium">Workflow looks good.</p>
              </div>
            )}
            {warnings.map(w => (
              <div
                key={w.id}
                className="rounded-md border p-3"
                style={{
                  borderColor: w.severity === 'error' ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.4)',
                  background:  w.severity === 'error' ? 'rgba(239,68,68,0.08)' : 'rgba(245,158,11,0.08)',
                }}
              >
                <div className="flex items-start gap-2">
                  {w.severity === 'error'
                    ? <AlertCircle   className="mt-0.5 h-3.5 w-3.5 shrink-0 text-red-400" />
                    : <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-yellow-400" />
                  }
                  <div>
                    <p
                      className="mb-0.5 text-[11px] font-semibold uppercase tracking-wide"
                      style={{ color: w.severity === 'error' ? '#f87171' : '#fbbf24' }}
                    >
                      {w.severity === 'error' ? 'Error' : 'Warning'}
                    </p>
                    <p
                      className="text-[11px] leading-relaxed"
                      style={{ color: w.severity === 'error' ? '#fca5a5' : '#fde68a' }}
                    >
                      {w.message}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Center — Canvas */}
        <div className="relative flex-1 bg-background">
          {executionOrder.length === 0 && nodes.filter(n => n.type === 'toolNode').length === 0 && (
            <div className="pointer-events-none absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 text-muted-foreground">
              <div className="rounded-full border border-dashed border-border p-4">
                <Zap className="h-8 w-8 opacity-30" />
              </div>
              <p className="text-sm font-medium">Workflow is empty</p>
              <p className="text-xs">Add tools from the left panel</p>
            </div>
          )}
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            nodeTypes={NODE_TYPES}
            defaultEdgeOptions={EDGE_DEFAULTS}
            fitView
            fitViewOptions={{ padding: 0.4 }}
            colorMode={theme}
            deleteKeyCode="Delete"
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        {/* Right — Audit details */}
        <div className="flex w-72 shrink-0 flex-col gap-5 overflow-y-auto border-l border-border bg-card/50 p-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Audit Details
          </p>

          {/* Name */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-foreground">
              Name <span className="text-destructive">*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Q2 Web Audit"
              className="rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          {/* Description */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-foreground">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={3}
              placeholder="Optional scope notes..."
              className="resize-none rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            />
          </div>

          {/* Target */}
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium text-foreground">
              Target <span className="text-destructive">*</span>
            </label>
            <div className="relative">
              <select
                value={targetId}
                onChange={e => setTargetId(e.target.value)}
                className="w-full appearance-none rounded-md border border-input bg-background px-3 py-2 pr-8 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <option value="">Select a target...</option>
                {targets.map(t => (
                  <option key={t.id} value={t.id}>{t.name} — {t.address}</option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            </div>
          </div>

          {/* Audit type */}
          <div className="flex flex-col gap-2">
            <label className="text-xs font-medium text-foreground">Audit Type</label>
            <p className="text-xs text-muted-foreground/60">
              Selecting a type pre-populates the recommended workflow.
            </p>
            <div className="flex flex-col gap-2">
              {(Object.entries(AUDIT_TYPE_META) as [AuditType, typeof AUDIT_TYPE_META[AuditType]][]).map(([type, meta]) => {
                const isActive = detectedType === type
                return (
                  <button
                    key={type}
                    onClick={() => handleTypeChange(type)}
                    className="flex items-start gap-3 rounded-md border p-3 text-left transition-colors"
                    style={{
                      borderColor: isActive ? 'rgba(255,255,255,0.25)' : 'rgba(255,255,255,0.07)',
                      background:  isActive ? 'rgba(255,255,255,0.06)' : 'transparent',
                    }}
                  >
                    <div className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md transition-colors ${
                      isActive ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
                    }`}>
                      {meta.icon}
                    </div>
                    <div>
                      <p className={`text-xs font-semibold ${isActive ? 'text-foreground' : 'text-muted-foreground'}`}>
                        {meta.label}
                      </p>
                      <p className="text-[11px] text-muted-foreground/60">{meta.description}</p>
                    </div>
                  </button>
                )
              })}

              {/* Custom badge — appears when tools are present but don't match a preset */}
              {detectedType === 'custom' && executionOrder.length > 0 && (
                <div className="flex items-center gap-3 rounded-md border border-purple-500/30 bg-purple-500/10 px-3 py-2.5">
                  <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-purple-500/20">
                    <Wand2 className="h-3.5 w-3.5 text-purple-400" />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-purple-300">Custom</p>
                    <p className="text-[11px] text-purple-400/70">Workflow modified from preset</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Execution order summary */}
          {executionOrder.length > 0 && (
            <div className="rounded-md border border-border bg-muted/20 p-3">
              <p className="mb-2 text-xs font-medium text-foreground">Execution order</p>
              <ol className="space-y-1.5">
                {executionOrder.map((tool, i) => (
                  <li key={i} className="flex items-center gap-2 text-xs">
                    <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-muted text-[10px] font-bold text-foreground">
                      {i + 1}
                    </span>
                    <span style={{ color: TOOL_META[tool].color }} className="font-semibold">
                      {TOOL_META[tool].label}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Create button */}
          <button
            onClick={handleCreate}
            disabled={!canCreate}
            className="mt-auto rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {createMutation.isPending ? 'Creating...' : 'Create Audit'}
          </button>
        </div>
      </div>
    </div>
  )
}
