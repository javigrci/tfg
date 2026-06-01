import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'

interface Props {
  className?: string
}

export function PageLoader({ className }: Props) {
  const { t } = useTranslation()
  return (
    <div className={cn('flex items-center justify-center h-64 text-muted-foreground', className)}>
      <Loader2 className="h-5 w-5 animate-spin mr-2" />
      {t('common.loading')}
    </div>
  )
}
