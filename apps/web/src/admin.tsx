import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ClipboardList, Plus, UserRound } from 'lucide-react'
import { ActivityFeed, ConfirmDialog, EmptyState, LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Dialog } from './components/ui/dialog'
import { HostOperations } from "./operations"
import { useState, type FormEvent } from 'react'
import { api, type AuditEvent, type Role, type Session, type Settings, type User } from './api'
import { Action, Field, FormError, Panel, errorMessage, roleLabels, type Translate } from './ui'

type Context = { session: Session; t: Translate }

function ServerDiagnostics({ t }: { t: Translate }) {
  const [expanded, setExpanded] = useState(false)
  const query = useQuery({
    queryKey: ['system-events'], enabled: expanded,
    queryFn: () => api<{ time: string; kind: 'started' | 'http_error' | 'cloud_check_failed'; status?: number; route?: string }[]>('/system/events'),
  })
  const titles = {
    started: t('Server запущен', 'Server started'),
    http_error: t('Ошибка API', 'API error'),
    cloud_check_failed: t('Ошибка связи с Cloud', 'Cloud connection failed'),
  }
  return <Panel>
    <SectionTitle title={t('Диагностика Server', 'Server diagnostics')}
      actions={<Action secondary onClick={() => {
        if (expanded) void query.refetch()
        else setExpanded(true)
      }}>{expanded ? t('Обновить журнал', 'Refresh log') : t('Показать журнал', 'Show log')}</Action>} />
    {expanded && <>
      <p className="mb-2 text-sm text-muted-foreground">{t('События с последнего запуска Server.', 'Events since the last Server start.')}</p>
      <FormError message={query.error ? errorMessage(query.error, t) : null} />
      {query.isPending ? <LoadingSkeleton label={t('Загрузка журнала', 'Loading log')} /> :
        !!query.data?.length && <ul className="max-h-64 divide-y divide-border overflow-y-auto text-sm">
          {query.data.map((event, index) => <li className="py-2" key={index}>
            <p>{titles[event.kind]}{event.status ? ` · HTTP ${event.status}` : ''}</p>
            <p className="break-words text-muted-foreground">{new Date(event.time).toLocaleString(t('ru', 'en'))}{event.route ? ` · ${event.route}` : ''}</p>
          </li>)}
        </ul>}
    </>}
  </Panel>
}

function AccountSessions({ session, t }: Context) {
  const [confirm, setConfirm] = useState(false)
  const client = useQueryClient()
  const key = ['account-sessions', session.user.id]
  const sessions = useQuery({
    queryKey: key,
    queryFn: () => api<{ current: boolean; last_seen_at: string; expires_at: string }[]>('/auth/sessions'),
  })
  const revoke = useMutation({
    mutationFn: () => api<void>('/auth/sessions/others', { method: 'DELETE', csrf: session.csrf_token }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: key }) },
  })
  const date = (value: string) => new Date(value).toLocaleString()
  return <Panel>
    <SectionTitle title={t('Мои сеансы', 'My sessions')}
      actions={<Action secondary disabled={!sessions.data?.some(row => !row.current) || revoke.isPending}
        onClick={() => setConfirm(true)}>{t('Завершить остальные', 'Sign out other sessions')}</Action>} />
    <FormError message={(sessions.error || revoke.error) && errorMessage(sessions.error || revoke.error, t)} />
    {sessions.isPending && <LoadingSkeleton label={t('Загрузка сеансов', 'Loading sessions')} />}
    <ul className="divide-y divide-border text-sm">
      {sessions.data?.map((row, index) => <li className="flex flex-wrap justify-between gap-2 py-2" key={index}>
        <span>{row.current ? t('Текущий сеанс', 'Current session') : t('Другой сеанс', 'Other session')}</span>
        <span className="text-muted-foreground">{date(row.last_seen_at)} · {t('до', 'until')} {date(row.expires_at)}</span>
      </li>)}
    </ul>
    {confirm && <ConfirmDialog title={t('Завершить другие сеансы?', 'Sign out other sessions?')}
      description={t('Текущий сеанс останется активным.', 'This session stays active.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Завершить', 'Sign out') }}
      close={() => setConfirm(false)} confirm={() => { setConfirm(false); revoke.mutate() }} />}
  </Panel>
}

export function SettingsPage({ settings, session, t, health }: Context & { settings: Settings; health: React.ReactNode }) {
  const client = useQueryClient()
  const writable = session.user.role === 'super_admin'
  const save = useMutation({
    mutationFn: (body: Omit<Settings, 'version'>) => api<Settings>('/settings', { method: 'PUT', csrf: session.csrf_token, body }),
    onSuccess: result => client.setQueryData(['settings'], result),
  })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const agent = String(fields.get('agent_url') ?? '').trim()
    save.mutate({
      organization: String(fields.get('organization')),
      instance_name: String(fields.get('instance_name')),
      agent_url: agent || null,
      heartbeat_seconds: Number(fields.get('heartbeat_seconds')),
      language: fields.get('language') as Settings['language'],
    })
  }

  return <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
    <Panel>
      <SectionTitle title={t('Параметры экземпляра', 'Instance settings')}
        actions={!writable ? <StatusBadge>{t('Только чтение', 'Read only')}</StatusBadge> : undefined} />
      <form key={JSON.stringify(settings)} className="grid gap-4" onSubmit={submit}>
        <fieldset disabled={!writable || save.isPending} className="grid min-w-0 gap-4 sm:grid-cols-2">
          <Field label={t('Название организации', 'Organization name')} name="organization" required maxLength={120} defaultValue={settings.organization} />
          <Field label={t('Имя экземпляра', 'Instance name')} name="instance_name" required maxLength={120} defaultValue={settings.instance_name} />
          <div className="min-w-0 sm:col-span-2"><Field label={t('Адрес сервера для агентов', 'Server address for agents')} name="agent_url" type="url" placeholder="https://deploycore.example" maxLength={512} defaultValue={settings.agent_url ?? ''} hint={t('HTTPS-адрес сервера. Укажите адрес, доступный компьютерам.', 'HTTPS server origin. Use an address reachable by managed computers.')} /></div>
          <Field label={t('Интервал heartbeat, с', 'Heartbeat interval, s')} name="heartbeat_seconds" type="number" required min={15} max={3600} defaultValue={settings.heartbeat_seconds} />
          <label className="grid gap-2 text-sm font-medium">
            {t('Язык интерфейса', 'Interface language')}
            <select name="language" className="input" defaultValue={settings.language}>
              <option value="ru">Русский</option><option value="en">English</option>
            </select>
          </label>
        </fieldset>
        <FormError message={save.error && errorMessage(save.error, t)} />
        {save.isSuccess && <p role="status" className="text-sm text-success">{t('Настройки сохранены.', 'Settings saved.')}</p>}
        {writable && <Action type="submit" disabled={save.isPending}>{t('Сохранить настройки', 'Save settings')}</Action>}
      </form>
    </Panel>
    <div className="grid content-start gap-4">
      <Panel><SectionTitle title={t('Состояние экземпляра', 'Instance health')} />
        <div className="mb-3 flex justify-between gap-3 text-sm"><span className="text-muted-foreground">{t('Версия DeployCore', 'DeployCore version')}</span><span className="font-mono text-info">{settings.version}</span></div>
        {health}
      </Panel>
      <AccountSessions session={session} t={t} />
      {writable && <ServerDiagnostics t={t} />}
      {writable && <HostOperations session={session} t={t} />}
    </div>
  </div>
}

function RoleSelector({ name = 'role', value, onChange, label, disabled, t }: {
  name?: string; value?: Role; onChange?: (role: Role) => void; label: string; disabled?: boolean; t: Translate
}) {
  return <select name={name} aria-label={label} className="input" value={value} defaultValue={value === undefined ? 'viewer' : undefined}
    disabled={disabled} onChange={onChange && (event => onChange(event.target.value as Role))}>
    {Object.entries(roleLabels(t)).map(([key, title]) => <option key={key} value={key}>{title}</option>)}
  </select>
}

function UserRow({ user, ownId, t, change }: { user: User; ownId: string; t: Translate; change: (id: string, role: Role) => void }) {
  const [role, setRole] = useState(user.role)
  return <li className="flex flex-wrap items-center gap-3 border-b border-border py-3 last:border-0">
    <UserRound className="size-4 shrink-0 text-info" aria-hidden />
    <span className="min-w-0 break-all text-sm font-medium">{user.username}{user.id === ownId && <span className="ml-2 text-sm text-muted-foreground">{t('(вы)', '(you)')}</span>}</span>
    <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
      <RoleSelector t={t} value={role} onChange={setRole} label={`${t('Роль', 'Role')} · ${user.username}`} />
      <Action type="button" secondary disabled={role === user.role} onClick={() => change(user.id, role)}>{t('Сменить роль', 'Change role')}</Action>
    </div>
  </li>
}

export function UsersPage({ session, t }: Context) {
  const client = useQueryClient()
  const [creating, setCreating] = useState(false)
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<User[]>('/users') })
  const create = useMutation({
    mutationFn: (body: { username: FormDataEntryValue | null; password: FormDataEntryValue | null; role: FormDataEntryValue | null }) =>
      api<User>('/users', { method: 'POST', csrf: session.csrf_token, body }),
    onSuccess: () => client.invalidateQueries({ queryKey: ['users'] }),
  })
  const change = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) =>
      api<User>(`/users/${id}/role`, { method: 'PATCH', csrf: session.csrf_token, body: { role } }),
    onSuccess: user => {
      void client.invalidateQueries({ queryKey: ['users'] })
      if (user.id === session.user.id) client.setQueryData<Session>(['session'], { ...session, user })
    },
  })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const fields = new FormData(form)
    create.mutate({ username: fields.get('username'), password: fields.get('password'), role: fields.get('role') }, {
      onSuccess: () => { form.reset(); setCreating(false) },
    })
  }

  return <>
    <Panel>
      <SectionTitle title={t('Учётные записи', 'Accounts')} actions={
        <Action onClick={() => { create.reset(); setCreating(true) }}><Plus className="size-4" aria-hidden />{t('Новый пользователь', 'New user')}</Action>
      } />
      {users.isPending && <LoadingSkeleton label={t('Загрузка пользователей', 'Loading users')} />}
      <FormError message={(users.error || change.error) && errorMessage(users.error || change.error, t)} />
      {users.data?.length === 0 && <EmptyState icon={UserRound} title={t('Пользователей пока нет', 'No users yet')} />}
      {!!users.data?.length && <ul>{users.data.map(user => <UserRow key={`${user.id}:${user.role}`} user={user} ownId={session.user.id} t={t}
        change={(id, role) => { if (!change.isPending) change.mutate({ id, role }) }} />)}</ul>}
    </Panel>
    {creating && <Dialog title={t('Новый пользователь', 'New user')} closeLabel={t('Закрыть', 'Close')} close={() => setCreating(false)}>
      <form className="grid gap-4" onSubmit={submit}>
        <Field label={t('Имя пользователя', 'Username')} name="username" required minLength={3} maxLength={64} autoComplete="off" />
        <Field label={t('Пароль', 'Password')} type="password" name="password" required minLength={12} maxLength={128} autoComplete="new-password" />
        <label className="grid gap-2 text-sm font-medium">{t('Роль', 'Role')}<RoleSelector t={t} label={t('Роль нового пользователя', 'New user role')} /></label>
        <FormError message={create.error && errorMessage(create.error, t)} />
        <Action type="submit" disabled={create.isPending}>{t('Создать пользователя', 'Create user')}</Action>
      </form>
    </Dialog>}
  </>
}

export function AuditPage({ t }: { t: Translate }) {
  const [filter, setFilter] = useState('')
  const events = useQuery({ queryKey: ['audit'], queryFn: () => api<AuditEvent[]>('/audit') })
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<User[]>('/users') })
  const names = new Map(users.data?.map(user => [user.id, user.username]))
  const actions: Record<string, string> = {
    login_succeeded: t('Вход выполнен', 'Sign-in succeeded'),
    login_failed: t('Неудачный вход', 'Sign-in failed'),
    logout: t('Выход', 'Sign-out'),
    user_created: t('Пользователь создан', 'User created'),
    role_changed: t('Роль изменена', 'Role changed'),
    settings_changed: t('Настройки изменены', 'Settings changed'),
    setup_completed: t('Настройка завершена', 'Setup completed'),
    enrollment_created: t('Выдан токен регистрации', 'Enrollment token issued'),
    enrollment_revoked: t('Токен регистрации отозван', 'Enrollment token revoked'),
    agent_revoked: t('Ключ агента отозван', 'Agent credential revoked'),
    device_deleted: t('Устройство удалено', 'Device deleted'),
  }
  const items = (events.data ?? []).map(event => ({
    key: event.id, title: actions[event.action] ?? event.action, time: event.created_at,
    detail: [...new Set([event.actor_id, event.target_id].filter((id): id is string => Boolean(id)))].map(id => names.get(id) ?? id).join(' · '),
    warning: event.action === 'login_failed' || event.action.endsWith('_revoked'),
  })).filter(item => `${item.title} ${item.detail}`.toLocaleLowerCase().includes(filter.trim().toLocaleLowerCase()))
  return <Panel>
    <SectionTitle title={t('Последние записи', 'Recent entries')} actions={events.data && <Action secondary onClick={() => void events.refetch()}>{t('Обновить', 'Refresh')}</Action>} />
    <div className="mb-4 max-w-md"><Field label={t('Поиск по событию или участнику', 'Search by event or participant')} value={filter} onChange={event => setFilter(event.target.value)} /></div>
    {events.isPending && <LoadingSkeleton label={t('Загрузка журнала', 'Loading audit events')} />}
    <FormError message={events.error && errorMessage(events.error, t)} />
    {events.data && (items.length ? <ActivityFeed items={items} />
      : <EmptyState icon={ClipboardList} title={filter ? t('Нет совпадений', 'No matches') : t('Событий пока нет', 'No events yet')} />)}
  </Panel>
}
