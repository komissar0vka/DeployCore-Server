import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, pollEvery, type Session } from './api'
import { HostOperations } from './operations'
import { LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, Field, FormError, Panel, errorMessage, type Translate } from './ui'

interface Updates {
  status: 'connected' | 'not_configured' | 'unavailable'
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
  const [cloudOpen, setCloudOpen] = useState(false)
  const [cloudProblem, setCloudProblem] = useState('')
  const [selectedRelease, setSelectedRelease] = useState('')
  const [channel, setChannel] = useState<'stable' | 'beta'>('stable')
  const updates = useMutation({ mutationFn: (choice: string) => api<Updates>(`/licenses/updates/${choice}`) })
  const query = useQuery({ queryKey: ['license'], queryFn: () => api<License>('/licenses'), refetchInterval: pollEvery(15_000) })
  const upload = useMutation({
    mutationFn: (body: unknown) => api<License>('/licenses/import', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: status => client.setQueryData(['license'], status),
  })
  const activate = useMutation({
    mutationFn: (body: { origin: string; token: string; license_key: string; release_key: string; ca: string | null }) =>
      api<License>('/licenses/cloud', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: status => {
      client.setQueryData(['license'], status)
      setCloudOpen(false)
      updates.reset()
    },
  })
  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (activate.isPending) return
    setCloudProblem('')
    const data = new FormData(event.currentTarget)
    const file = data.get('ca')
    if (file instanceof File && file.size > 65536) {
      setCloudProblem(t('Файл сертификата превышает 64 КиБ.', 'The certificate file exceeds 64 KiB.'))
      return
    }
    const read = (key: string) => String(data.get(key) ?? '').trim()
    try {
      activate.mutate({ origin: read('origin'), token: read('token'), license_key: read('license_key'),
        release_key: read('release_key'), ca: file instanceof File && file.size ? await file.text() : null })
    } catch {
      setCloudProblem(t('Не удалось прочитать сертификат.', 'Could not read the certificate.'))
    }
  }
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
          setChannel(event.target.value as 'stable' | 'beta'); updates.reset(); setSelectedRelease('')
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
        {updates.data.status === 'not_configured' ? <p>{t('Cloud не подключён. Локальная лицензия продолжает действовать.', 'Cloud is not connected. The local license remains active.')}</p>
          : updates.data.status === 'unavailable' ? <p>{t('Не удалось получить проверенный каталог. Повтори проверку позже.', 'Could not retrieve a verified catalog. Check again later.')}</p>
          : updates.data.releases.length ? <ul>{updates.data.releases.map(release =>
          <li key={release.version}>{release.version} · {new Date(release.published_at).toLocaleDateString()}</li>)}</ul>
          : <p>{t('В этом канале релизов пока нет.', 'This channel has no releases yet.')}</p>}
      </div>}
    </Panel>
    {session.user.role === 'super_admin' && selectedRelease &&
      <HostOperations t={t} session={session} update={{ action: 'update', channel, version: selectedRelease }} />}
    {session.user.role === 'super_admin' && <Panel>
      <SectionTitle title={t('Подключение к Cloud', 'Cloud connection')} actions={
        <Action secondary onClick={() => { activate.reset(); setCloudOpen(value => !value) }}>
          {cloudOpen ? t('Закрыть форму', 'Close form') : t('Активировать через Cloud', 'Activate via Cloud')}
        </Action>
      } />
      {activate.isSuccess && <p role="status" className="text-sm">{t('Cloud подключён. Лицензия активирована.', 'Cloud connected and license activated.')}</p>}
      {cloudOpen && <form className="grid max-w-2xl gap-3" onSubmit={connect}>
        <Field name="origin" type="url" maxLength={512} required label={t('Адрес Cloud (HTTPS)', 'Cloud address (HTTPS)')} />
        <Field name="token" type="password" autoComplete="off" minLength={43} maxLength={43} required label={t('Токен активации', 'Activation token')} />
        <Field name="license_key" minLength={43} maxLength={43} required label={t('Публичный ключ лицензий', 'License public key')} />
        <Field name="release_key" minLength={43} maxLength={43} required label={t('Публичный ключ обновлений', 'Release public key')} />
        <Field name="ca" type="file" accept=".pem,.crt" label={t('Сертификат доверия Cloud (если требуется)', 'Cloud CA certificate (if required)')} />
        <FormError message={cloudProblem || (activate.error && errorMessage(activate.error, t))} />
        <Action type="submit" disabled={activate.isPending}>{t('Подключить и активировать', 'Connect and activate')}</Action>
      </form>}
    </Panel>}
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
