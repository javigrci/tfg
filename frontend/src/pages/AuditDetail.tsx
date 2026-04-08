import { useParams } from 'react-router-dom'

export default function AuditDetail() {
  const { id } = useParams<{ id: string }>()
  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground">Audit #{id}</h1>
      <p className="text-muted-foreground mt-1">Audit details, scans and findings</p>
    </div>
  )
}
