import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, type Session } from './api'
import { LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, FormError, Panel, errorMessage, type Translate } from './ui'

interface License {
  instance_id: string
  edition: 'free' | 'business' | 'enterprise'
  status: 'free' | 'valid' | 'grace' | 'fallback'
  limit: number
  managed: number
  expires_at: string | null
}

export function LicensesPage({ session, t }: { session: Session; t: Translate }) {
  const client = useQueryClient()
  const [file, setFile] = useState<File>()
  const [problem, setProblem] = useState('')
  const query = useQuery({ queryKey: ['license'], queryFn: () => api<License>('/licenses'), refetchInterval: 15_000 })
  const upload = useMutation({
    mutationFn: (body: unknown) => api<License>('/licenses/import', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: status => client.setQueryData(['license'], status),
  })
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setProblem('')
    if (!file || upload.isPending) return
    if (file.size > 24 * 1024) {
      setProblem(t('Файл лицензии превышает 24 КиБ.', 'The license file exceeds 24 KiB.'))
      return
    }
    try { upload.mutate(JSON.parse(await file.text())) }
    catch { setProblem(t('Не удалось прочитать JSON лицензии.', 'Could not read the license JSON.')) }
  }
  const data = query.data
  return <div className="grid gap-4">
    <Panel>
      <SectionTitle title={t('Лимит управления', 'Management allowance')} />
      {query.isPending && <LoadingSkeleton label={t('Загрузка лицензии', 'Loading license')} />}
      <FormError message={query.error && errorMessage(query.error, t)} />
      {data && <dl className="grid gap-4 text-sm sm:grid-cols-2">
        <div><dt>{t('Редакция', 'Edition')}</dt><dd className="capitalize">{data.edition}</dd></div>
        <div><dt>{t('Управляемые устройства', 'Managed devices')}</dt><dd>{data.managed} / {data.limit}</dd></div>
        <div><dt>{t('Состояние', 'Status')}</dt><dd><StatusBadge tone={data.status === 'fallback' || data.status === 'grace' ? 'warning' : 'success'}>
          {{ free: 'Free', valid: t('Активна', 'Active'), grace: t('Льготный период', 'Grace period'),
            fallback: t('Выдача недоступна, применяется Free', 'Grant unavailable, using Free') }[data.status]}
        </StatusBadge></dd></div>
        <div><dt>{t('UUID экземпляра', 'Instance UUID')}</dt><dd className="break-all font-mono">{data.instance_id}</dd></div>
        {data.expires_at && <div><dt>{t('Действует до', 'Expires')}</dt><dd>{new Date(data.expires_at).toLocaleString(t('ru', 'en'))}</dd></div>}
      </dl>}
      {data && data.managed > data.limit && <p className="mt-3 text-sm">{t('Достигнут лимит. Существующие устройства продолжают работу.', 'The limit is reached. Existing devices remain managed.')}</p>}
    </Panel>
    {session.user.role === 'super_admin' && <Panel>
      <SectionTitle title={t('Импорт подписанной лицензии', 'Import signed license')} />
      <form className="grid max-w-lg gap-3" onSubmit={submit}>
        <label className="grid gap-2 text-sm">{t('Файл лицензии', 'License file')}
          <input className="input" type="file" accept=".json,application/json" onChange={event => {
            setFile(event.target.files?.[0]); setProblem(''); upload.reset()
          }} />
        </label>
        <FormError message={problem || (upload.error && errorMessage(upload.error, t))} />
        {upload.isSuccess && <p role="status" className="text-sm">{t('Лицензия проверена и сохранена.', 'The license has been verified and saved.')}</p>}
        <Action type="submit" disabled={!file || upload.isPending}>{t('Импортировать', 'Import')}</Action>
      </form>
    </Panel>}
  </div>
}
