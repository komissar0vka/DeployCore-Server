import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, type Session } from './api'
import { LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, FormError, Panel, errorMessage, type Translate } from './ui'

interface Updates {
  current_version: string
  releases: { version: string; published_at: string }[]
}

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
  const [channel, setChannel] = useState<'stable' | 'beta'>('stable')
  const updates = useMutation({ mutationFn: (choice: string) => api<Updates>(`/licenses/updates/${choice}`) })
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
    <Panel>
      <SectionTitle title={t('Обновления Server', 'Server updates')} />
      <label className="grid max-w-xs gap-2 text-sm">
        {t('Канал релизов', 'Release channel')}
        <select className="input" value={channel} onChange={event => {
          setChannel(event.target.value as 'stable' | 'beta'); updates.reset()
        }}>
          <option value="stable">Stable</option><option value="beta">Beta</option>
        </select>
      </label>
      <div className="mt-3">
        <Action onClick={() => updates.mutate(channel)} disabled={updates.isPending}>{t('Проверить релизы', 'Check releases')}</Action>
      </div>
      <FormError message={updates.error && errorMessage(updates.error, t)} />
      {updates.data && <div className="mt-3 text-sm">
        <p>{t('Текущая версия', 'Current version')} {updates.data.current_version}</p>
        {updates.data.releases.length ? <ul>{updates.data.releases.map(release =>
          <li key={release.version}>{release.version} · {new Date(release.published_at).toLocaleDateString()}</li>)}</ul>
          : <p>{t('В этом канале релизов пока нет.', 'This channel has no releases yet.')}</p>}
      </div>}
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
