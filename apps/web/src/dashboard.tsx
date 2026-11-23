import { useQuery } from '@tanstack/react-query'
import { ArrowDownToLine, ClipboardList, ListTodo, Monitor, Package, Radio, WifiOff } from 'lucide-react'
import type { ReactNode } from 'react'
import type { JobScope } from './console-shell'
import { api } from './api'
import { ActivityFeed, EmptyState, LoadingSkeleton, QuickAction, SectionTitle, StatCard } from './design'
import { Action, errorMessage, FormError, Panel, type Translate } from './ui'

interface FleetEntry {
  id?: number
  action: string
  hostname?: string | null
  created_at: string
}

interface FleetSummary {
  total: number
  online: number
  offline: number
  versions: Record<string, number>
  events: FleetEntry[]
  errors: FleetEntry[]
}

export function FleetActivity({ items, t, warning }: { items: FleetEntry[]; t: Translate; warning?: boolean }) {
  const labels: Record<string, string> = {
    registered: t('Компьютер зарегистрирован', 'Computer enrolled'),
    reconnected: t('Связь восстановлена', 'Connection restored'),
    agent_recovered: t('Ключ восстановлен', 'Agent key recovered'),
    inventory_failed: t('Не удалось обновить инвентарь', 'Inventory refresh failed'),
    recovery_issued: t('Выдан токен восстановления', 'Recovery token issued'),
    inventory_updated: t('Инвентаризация обновлена', 'Inventory updated'),
    name_changed: t('Имя компьютера изменено', 'Hostname changed'),
    agent_revoked: t('Ключ агента отозван', 'Agent key revoked'),
    device_deleted: t('Компьютер удалён', 'Computer deleted'),
    login_failed: t('Неудачный вход', 'Sign-in failed'),
  }
  return <ActivityFeed items={items.map((item, index) => ({
    key: item.id ?? index, title: labels[item.action] ?? item.action, detail: item.hostname ?? undefined, time: item.created_at, warning,
  }))} />
}

export function useFleetSummary() {
  return useQuery({ queryKey: ['fleet-summary'], queryFn: () => api<FleetSummary>('/devices/summary'), refetchInterval: 15_000 })
}

function FleetChart({ online, offline, total, t }: { online: number; offline: number; total: number; t: Translate }) {
  const percent = Math.max(0, Math.min(100, Math.round(100 * online / total)))
  return <div className="flex flex-wrap items-center justify-center gap-5 sm:justify-start">
    <div className="relative grid size-32 shrink-0 place-items-center">
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 120 120" aria-hidden>
        <circle cx="60" cy="60" r="50" fill="none" strokeWidth="9" className="stroke-danger-graph" />
        <circle cx="60" cy="60" r="50" fill="none" strokeWidth="9" pathLength="100"
          strokeDasharray={`${percent} 100`} className="stroke-success-graph" />
      </svg>
      <div className="text-center"><strong className="block text-2xl tabular-nums">{percent}%</strong><span className="text-xs text-muted-foreground">{t('онлайн', 'online')}</span></div>
    </div>
    <dl className="grid min-w-23 gap-2 text-sm">
      <div className="flex items-center justify-between gap-3"><dt className="flex items-center gap-2 text-muted-foreground"><span className="size-2 rounded-full bg-success-graph" />{t('Онлайн', 'Online')}</dt><dd className="tabular-nums">{online}</dd></div>
      <div className="flex items-center justify-between gap-3"><dt className="flex items-center gap-2 text-muted-foreground"><span className="size-2 rounded-full bg-danger-graph" />{t('Офлайн', 'Offline')}</dt><dd className="tabular-nums">{offline}</dd></div>
    </dl>
  </div>
}

export function Dashboard({ t, openInstaller, openDevices, openInventory, openJobs, openAgents, health }: {
  t: Translate
  openInstaller?: () => void
  openDevices: (status?: 'online' | 'offline') => void
  openInventory: () => void
  openJobs: (scope?: JobScope, job?: string) => void
  openAgents: (version?: string) => void
  health: ReactNode
}) {
  const summary = useFleetSummary()
  const catalog = useQuery({ queryKey: ['packages', 'count'], queryFn: () => api<{ total: number }>('/packages?limit=1') })
  const jobs = useQuery({ queryKey: ['deployments', 'count'], queryFn: () => api<{ active: number; problem: number; items: { id: string; package_name: string; version: string; created_at: string }[] }>('/deployments?scope=problem&limit=5'), refetchInterval: 15_000 })
  const data = summary.data
  return <div className="grid gap-4">
    {summary.isError && <div className="grid gap-2">
      <FormError message={errorMessage(summary.error, t)} />
      <Action secondary disabled={summary.isFetching} onClick={() => void summary.refetch()}>{t('Повторить', 'Retry')}</Action>
    </div>}
    {summary.isPending ? <Panel><LoadingSkeleton label={t('Загрузка сводки', 'Loading fleet summary')} /></Panel> :
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 xl:grid-cols-6">
        <StatCard label={t('Всего компьютеров', 'Total computers')} value={data?.total} icon={Monitor} onClick={() => openDevices()} />
        <StatCard label={t('Онлайн', 'Online')} value={data?.online} icon={Radio} tone="green" onClick={() => openDevices('online')} />
        <StatCard label={t('Офлайн', 'Offline')} value={data?.offline} icon={WifiOff} tone="red" onClick={() => openDevices('offline')} />
        <StatCard label={t('Программ в каталоге', 'Catalog programs')} value={catalog.data?.total} icon={Package} tone="blue"
          unavailable={catalog.isError ? t('Недоступно', 'Unavailable') : undefined} />
        <StatCard label={t('Активных заданий', 'Active jobs')} icon={ListTodo} value={jobs.data?.active} onClick={() => openJobs('active')}
          unavailable={jobs.isError ? t('Недоступно', 'Unavailable') : undefined} />
        <StatCard label={t('Проблемных заданий', 'Jobs requiring attention')} icon={ListTodo} value={jobs.data?.problem} tone="red"
          onClick={() => openJobs('problem')} unavailable={jobs.isError ? t('Недоступно', 'Unavailable') : undefined} />
      </div>}

    <div className="grid min-w-0 items-start gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <Panel>
        <SectionTitle title={t('Статус устройств', 'Device status')} />
        {summary.isPending ? <LoadingSkeleton label={t('Загрузка состояния устройств', 'Loading device status')} rows={2} />
          : data?.total ? <FleetChart total={data.total} online={data.online} offline={data.offline} t={t} />
          : <EmptyState icon={Monitor} title={data ? t('Компьютеры ещё не подключены', 'No computers connected yet') : t('Сводка недоступна', 'Summary unavailable')} />}
        {!!data?.total && <div className="mt-4 border-t border-border pt-3">
          <h3 className="text-xs font-medium text-muted-foreground">{t('Версии агентов', 'Agent versions')}</h3>
          <dl className="mt-2 flex flex-wrap gap-2">{Object.entries(data.versions).map(([version, count]) => <div className="flex gap-2 rounded-lg bg-muted px-2 py-1 text-xs" key={version}><dt><button type="button" className="text-primary hover:underline" onClick={() => openAgents(version)}>{version}</button></dt><dd className="text-muted-foreground">{count}</dd></div>)}</dl>
        </div>}
      </Panel>
      <Panel>
        <SectionTitle title={t('Требуют внимания', 'Requires attention')} />
        {jobs.isPending && <LoadingSkeleton label={t('Загрузка заданий', 'Loading jobs')} rows={3} />}
        <FormError message={jobs.error && errorMessage(jobs.error, t)} />
        {jobs.data?.items.length === 0 && <EmptyState title={t('Проблемных заданий нет', 'No jobs require attention')} />}
        <ul className="divide-y divide-border">{jobs.data?.items.map(job => <li key={job.id} className="flex flex-wrap items-center justify-between gap-2 py-3 text-sm">
          <button type="button" onClick={() => openJobs('problem', job.id)} className="min-w-0 break-words text-start font-medium text-primary hover:underline">
            {job.package_name} · {job.version}
          </button>
          <time dateTime={job.created_at} className="text-xs text-muted-foreground">{new Date(job.created_at).toLocaleString(document.documentElement.lang)}</time>
        </li>)}</ul>
      </Panel>
    </div>

    <div className="grid min-w-0 items-start gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Panel>
        <SectionTitle title={t('Последние события', 'Recent events')} />
        {summary.isPending ? <LoadingSkeleton label={t('Загрузка событий', 'Loading events')} />
          : data?.events.length ? <FleetActivity items={data.events.slice(0, 6)} t={t} />
          : <EmptyState title={data ? t('Событий пока нет', 'No events yet') : t('События недоступны', 'Events unavailable')} />}
        {!!data?.errors.length && <div className="mt-4 border-t border-border pt-4">
          <SectionTitle title={t('Предупреждения', 'Warnings')} />
          <FleetActivity items={data.errors.slice(0, 3)} t={t} warning />
        </div>}
      </Panel>
      <div className="grid min-w-0 gap-4">
        <Panel>
          <SectionTitle title={t('Активные задания', 'Active jobs')} />
          {jobs.isPending ? <LoadingSkeleton label={t('Загрузка заданий', 'Loading jobs')} rows={2} />
            : jobs.data?.active ? <QuickAction icon={ListTodo} label={t('Открыть очередь', 'Open queue')} onClick={() => openJobs('active')} />
            : <EmptyState icon={ListTodo} title={jobs.isError ? t('Очередь недоступна', 'Queue unavailable') : t('Активных заданий нет', 'No active jobs')} />}
        </Panel>
        <Panel>
          <SectionTitle title={t('Быстрые действия', 'Quick actions')} />
          <div className="grid gap-2">
            <QuickAction label={t('Открыть устройства', 'Open devices')} icon={Monitor} onClick={() => openDevices()} />
            <QuickAction label={t('Посмотреть инвентаризацию', 'View inventory')} icon={ClipboardList} onClick={openInventory} />
            <QuickAction label={t('Мониторинг агентов', 'Agent monitoring')} icon={Radio} onClick={() => openAgents()} />
            {openInstaller && <QuickAction label={t('Скачать и настроить агент', 'Download and configure agent')} icon={ArrowDownToLine} onClick={openInstaller} />}
          </div>
        </Panel>
      </div>
    </div>
    {health}
  </div>
}
