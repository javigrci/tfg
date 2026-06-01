import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

interface Props {
  onRetry?: () => void
  message?: string
  className?: string
}

export function PageError({ onRetry, message, className }: Props) {
  const { t } = useTranslation()
  return (
    <div className={cn('flex flex-col items-center justify-center h-64 gap-3 text-muted-foreground', className)}>
      <p className="text-sm">{message ?? t('common.errorLoading')}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="text-xs text-blue-400 hover:underline"
        >
          {t('common.retry')}
        </button>
      )}
    </div>
  )
}
