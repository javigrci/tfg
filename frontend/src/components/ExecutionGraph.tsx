import { useTranslation } from 'react-i18next'
import { ArrowRight } from 'lucide-react'
import { toColumns, type ChainGraphResponse, type ChainType } from '@/lib/chainGraph'

const TYPE_COLOR: Record<ChainType, string> = {
  web_port:   'bg-purple-500/10 text-purple-400 border-purple-500/20',
  technology: 'bg-pink-500/10 text-pink-400 border-pink-500/20',
  path:       'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
}

/** Grafo de ejecución de solo lectura (spec 005 / FR-011). No es manipulable. */
export function ExecutionGraph({ graph }: { graph: ChainGraphResponse }) {
  const { t } = useTranslation()
  const columns = toColumns(graph)

  if (graph.notes.includes('single_tool')) {
    return <p className="text-sm text-muted-foreground">{t('auditNew.graph.single')}</p>
  }

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2 overflow-x-auto pb-1">
        {columns.map((col, ci) => (
          <div key={col.level} className="flex items-start gap-2">
            <div className="flex flex-col gap-2">
              {col.tools.map(box => (
                <div
                  key={box.tool}
                  className="rounded-lg border border-border bg-card px-3 py-2 min-w-[7rem]"
                >
                  <p className="text-sm font-semibold text-foreground capitalize">{box.tool}</p>
                  {box.produces.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {box.produces.map(p => (
                        <span
                          key={p}
                          className={`inline-flex rounded-full border px-1.5 py-0 text-[10px] ${TYPE_COLOR[p]}`}
                        >
                          {t(`auditNew.graph.type.${p}`)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
            {ci < columns.length - 1 && (
              <ArrowRight className="mt-3 h-4 w-4 shrink-0 text-muted-foreground" />
            )}
          </div>
        ))}
      </div>

      {graph.notes.includes('nmap_missing_web_generic') && (
        <p className="text-xs text-yellow-400">{t('auditNew.graph.nmapMissing')}</p>
      )}
      {graph.refeed.length > 0 && (
        <p className="text-xs text-muted-foreground">{t('auditNew.graph.refeed')}</p>
      )}
    </div>
  )
}
