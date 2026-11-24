import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowDown, ArrowLeft, ArrowUp, ArrowUpDown, ArrowDownToLine, LayoutGrid, List, Monitor, MoreHorizontal } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useFleetSummary } from './dashboard'
import type { DeviceStatusFilter } from './console-shell'
import { ActivityFeed, ConfirmDialog, DataTable, DeviceCard, EmptyState, LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Dropdown } from './components/ui/dropdown'
import { DeviceGroupsDialog } from './groups'
import { api, pollEvery, type Session } from './api'
import { Action, errorMessage, Field, FormError, Panel, type Translate } from './ui'

interface Device {
  id: string
  hostname: string
  fqdn: string
  network_name: string
  domain_joined: boolean
  ips: string[]
  os_version: string
  agent_version: string
  uptime_seconds: number
  last_seen_at: string
  online: boolean
  agent_revoked: boolean
  management_state?: "managed" | "retired"
}

interface DeviceDetail {
  device: Device
  inventory: {
    collected_at: string
    hardware: {
      manufacturer?: string
      model?: string
      os: { version: string; build: string; architecture: string }
      cpus: { model: string; cores: number; threads: number }[]
      ram_bytes: number
      disks: { letter: string; size_bytes: number; free_bytes: number; filesystem?: string; label?: string }[]
      interfaces: { name: string; ips: string[]; mac?: string }[]
    }
  } | null
  software: { name: string; version: string; publisher: string }[]
  events: { id: number; action: string; created_at: string }[]
}

interface Token {
  id: string
  label: string
  expires_at: string
  revoked_at: string | null
  device_id: string | null
  max_uses: number
  uses: number
}

interface Props { session: Session; t: Translate }
const pageSize = 25
const stamp = (value: string) => new Date(value).toLocaleString(document.documentElement.lang)
const gib = (bytes: number) => (bytes / 1024 ** 3).toLocaleString(document.documentElement.lang, { maximumFractionDigits: 1 })

function DeviceStatus({ device, t }: { device: Device; t: Translate }) {
  if (device.management_state === 'retired') return <StatusBadge>{t('Снято с управления', 'Retired')}</StatusBadge>
  return <StatusBadge tone={device.online ? 'success' : device.agent_revoked ? 'warning' : 'danger'}>
    {device.agent_revoked ? t('Ключ отозван', 'Revoked') : device.online ? t('Онлайн', 'Online') : t('Офлайн', 'Offline')}
  </StatusBadge>
}

function SecretBox({ value, t, close }: { value: string; t: Translate; close: () => void }) {
  const [copied, setCopied] = useState(false)
  return <div className="grid gap-3 rounded-xl border border-ring bg-primary-soft p-4">
    <label className="grid gap-2 text-sm font-medium">
      {t('Токен показывается один раз. Скопируйте его перед закрытием.', 'The token is shown once. Copy it before closing.')}
      <input className="input w-full font-mono" value={value} readOnly onFocus={event => event.currentTarget.select()} />
    </label>
    <div className="flex flex-wrap gap-2">
      <Action type="button" onClick={() => void navigator.clipboard.writeText(value).then(() => setCopied(true), () => setCopied(false))}>
        {copied ? t('Скопировано', 'Copied') : t('Копировать', 'Copy')}
      </Action>
      <Action type="button" secondary onClick={close}>{t('Закрыть токен', 'Close token')}</Action>
    </div>
  </div>
}

type SortKey = 'hostname' | 'status' | 'os' | 'agent' | 'last_seen'

export function DevicesPage({ session, t, openInstaller, initialSearch = '', initialStatus = 'all', selected, onSelect, onFilter, inventory, monitoring, agentVersion, openHistory, onSoftware }: Props & {
  openInstaller: () => void
  initialSearch?: string
  initialStatus?: DeviceStatusFilter
  selected?: string
  onSelect: (device?: string) => void
  onSoftware: (deviceId: string, deviceName: string) => void
  onFilter: (query: string, status: DeviceStatusFilter, version?: string) => void
  monitoring: boolean
  agentVersion?: string
  openHistory: (id: string) => void
  inventory: boolean
}) {
  const [search, setSearch] = useState(initialSearch)
  const term = initialSearch
  const status = initialStatus
  const [page, setPage] = useState(0)
  const [management, setManagement] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; direction: 'asc' | 'desc' }>({ key: 'hostname', direction: 'asc' })
  const [display, setDisplay] = useState<'auto' | 'table' | 'cards'>('auto')
  const [selection, setSelection] = useState(new Map<string, string>())
  const [copyStatus, setCopyStatus] = useState('')
  const [openGroups, setOpenGroups] = useState(false)
  const fleet = useFleetSummary()
  const devices = useQuery({
    queryKey: ['devices', term, status, page, sort.key, sort.direction, agentVersion, management], enabled: !selected,
    refetchInterval: monitoring ? pollEvery(15_000) : false,
    queryFn: () => api<{ items: Device[]; total: number }>(`/devices?${new URLSearchParams({
      q: term, status, ...(agentVersion ? { agent_version: agentVersion } : {}), ...(management ? { management_state: management } : {}), offset: String(page * pageSize), limit: String(pageSize), sort: sort.key, direction: sort.direction,
    })}`),
  })
  if (selected) return <Computer key={selected} id={selected} session={session} t={t} back={() => onSelect()} inventory={inventory} openHistory={openHistory} onSoftware={onSoftware} />

  const items = devices.data?.items ?? []
  const pageSelected = items.length > 0 && items.every(device => selection.has(device.id))
  const columns: { label: string; key?: SortKey }[] = [
    { label: t('Устройство', 'Device'), key: 'hostname' },
    { label: t('Статус', 'Status'), key: 'status' },
    { label: 'IP' },
    { label: t('ОС', 'OS'), key: 'os' },
    { label: t('Агент', 'Agent'), key: 'agent' },
    { label: t('Последняя активность', 'Last seen'), key: 'last_seen' },
  ]

  function changeSort(key: SortKey) {
    setSort(current => ({ key, direction: current.key === key && current.direction === 'asc' ? 'desc' : 'asc' }))
    setPage(0)
  }

  function selectRows(rows: Device[], checked: boolean) {
    setCopyStatus('')
    setSelection(current => {
      const next = new Map(current)
      for (const device of rows) {
        if (checked) next.set(device.id, device.hostname)
        else next.delete(device.id)
      }
      return next
    })
  }

  function clearSelection() {
    setSelection(new Map())
    setCopyStatus('')
  }

  async function copySelection() {
    try {
      await navigator.clipboard.writeText([...selection.values()].join('\n'))
      setCopyStatus(t('Имена скопированы.', 'Names copied.'))
    } catch {
      setCopyStatus(t('Не удалось скопировать имена.', 'Could not copy names.'))
    }
  }

  function deviceMenu(device: Device) {
    return <Dropdown label={t('Действия для', 'Actions for') + ' ' + device.hostname} trigger={<MoreHorizontal className="size-5" aria-hidden />}>
      {close => <button type="button" className="block w-full rounded-md px-2 py-2 text-left text-sm hover:bg-muted"
        onClick={() => { close(); onSelect(device.id) }}>
        {inventory ? t('Открыть инвентаризацию', 'Open inventory') : t('Открыть карточку', 'Open device')}
      </button>}
    </Dropdown>
  }

  function rowCheckbox(device: Device) {
    return <input type="checkbox" className="size-4" checked={selection.has(device.id)}
      aria-label={t('Выбрать', 'Select') + ' ' + device.hostname}
      onChange={event => selectRows([device], event.target.checked)} />
  }

  return <div className="grid gap-4">
    {openGroups && <DeviceGroupsDialog session={session} t={t} selected={selection} close={() => setOpenGroups(false)} />}
    {!inventory && !monitoring && <div><Action secondary onClick={() => setOpenGroups(true)}>{t('Группы устройств', 'Device groups')}</Action></div>}
    <Panel>
      <form className="flex flex-wrap items-end gap-3" onSubmit={event => {
        event.preventDefault()
        if (term === search.trim() && page === 0) void devices.refetch()
        onFilter(search.trim(), status, agentVersion)
        setPage(0)
      }}>
        <Field label={t('Имя, FQDN или IP', 'Hostname, FQDN or IP')} value={search} maxLength={120} onChange={event => setSearch(event.target.value)} />
        <label className="grid gap-2 text-sm font-medium">{t('Статус', 'Status')}
          <select className="input" value={status} onChange={event => {
            onFilter(term, event.target.value as DeviceStatusFilter, agentVersion)
          }}>
            <option value="all">{t('Все', 'All')}</option>
            <option value="online">{t('Онлайн', 'Online')}</option>
            <option value="offline">{t('Офлайн', 'Offline')}</option>
            <option value="revoked">{t('Ключ отозван', 'Revoked')}</option>
          </select>
        </label>
        <label className="grid min-w-0 gap-2 text-sm">{t('Управление', 'Management')}
          <select className="input" value={management} onChange={event => { setManagement(event.target.value); setPage(0) }}>
            <option value="">{t('Все', 'All')}</option>
            <option value="managed">{t('Управляемые', 'Managed')}</option>
            <option value="retired">{t('Снятые с управления', 'Retired')}</option>
          </select>
        </label>
        {monitoring && <label className="grid min-w-0 gap-2 text-sm">{t('Версия агента', 'Agent version')}
          <select className="input" value={agentVersion ?? ''} disabled={fleet.isPending} onChange={event => onFilter(term, status, event.target.value || undefined)}>
            <option value="">{t('Все версии', 'All versions')}</option>
            {[...new Set([...Object.keys(fleet.data?.versions ?? {}), ...(agentVersion ? [agentVersion] : [])])].map(version =>
              <option key={version} value={version}>{version} {fleet.data?.versions[version] != null ? `(${fleet.data.versions[version]})` : ''}</option>)}
          </select>
          {fleet.isError && <FormError message={errorMessage(fleet.error, t)} />}
        </label>}
        <Action type="submit">{t('Поиск', 'Search')}</Action>
        <Action secondary type="button" onClick={() => void devices.refetch()} disabled={devices.isFetching}>{t('Обновить', 'Refresh')}</Action>
      </form>
    </Panel>

    <Panel>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold">{inventory ? t('Снимки инвентаризации', 'Inventory snapshots') : monitoring ? t('Связь с агентами', 'Agent connectivity') : t('Список устройств', 'Device list')}
          {devices.data && <span className="ml-2 text-sm font-medium tabular-nums text-muted-foreground">{devices.data.total}</span>}
        </h2>
        <div className="flex gap-1 rounded-lg border border-border p-0.5">
          {([
            ['table', List, t('Таблица', 'Table')], ['cards', LayoutGrid, t('Карточки', 'Cards')],
          ] as const).map(([mode, Icon, label]) => <button key={mode} type="button" aria-label={label} title={label}
            aria-pressed={display === mode} onClick={() => setDisplay(mode)}
            className={`rounded-md p-2 hover:bg-muted ${display === mode ? 'bg-primary-soft text-primary' : 'text-muted-foreground'}`}>
            <Icon className="size-4" aria-hidden />
          </button>)}
        </div>
      </div>
      {devices.isPending && <LoadingSkeleton label={t('Загрузка…', 'Loading…')} />}
      <FormError message={devices.error && errorMessage(devices.error, t)} />
      {devices.data?.items.length === 0 && <EmptyState icon={Monitor}
        title={term || status !== 'all' || agentVersion || management ? t('Нет устройств по выбранным условиям', 'No devices match the selected filters') : t('Устройств пока нет', 'No devices yet')}
        action={term || status !== 'all' || agentVersion || management
          ? <Action secondary onClick={() => { setManagement(''); setPage(0); onFilter('', 'all') }}>{t('Сбросить фильтры', 'Clear filters')}</Action>
          : session.user.role !== 'viewer' ? <Action secondary onClick={openInstaller}>{t('Установка агента', 'Agent installation')}</Action> : undefined} />}
      {!!items.length && <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input type="checkbox" className="size-4" checked={pageSelected}
            ref={input => { if (input) input.indeterminate = !pageSelected && items.some(device => selection.has(device.id)) }}
            onChange={event => selectRows(items, event.target.checked)} />
          {t('Выбрать страницу', 'Select page')}
        </label>
        <div className="flex min-w-0 max-w-full items-center gap-2 text-sm">
          <label htmlFor="device-sort">{t('Сортировка', 'Sort by')}</label>
          <select id="device-sort" className="input w-36 sm:w-auto" value={sort.key} onChange={event => changeSort(event.target.value as SortKey)}>
            {columns.map(column => column.key && <option key={column.key} value={column.key}>{column.label}</option>)}
          </select>
          <button type="button" className="shrink-0 rounded-md p-2 hover:bg-muted" aria-label={t('Изменить направление сортировки', 'Reverse sort direction')}
            onClick={() => changeSort(sort.key)}>{sort.direction === 'asc' ? <ArrowUp className="size-4" aria-hidden /> : <ArrowDown className="size-4" aria-hidden />}</button>
        </div>
      </div>}
      {selection.size > 0 && <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg bg-primary-soft p-2 text-sm">
        <span className="px-2 font-semibold text-primary">{t('Выбрано', 'Selected')}: {selection.size}</span>
        <Action secondary type="button" onClick={() => void copySelection()}>{t('Копировать имена', 'Copy names')}</Action>
        <Action secondary type="button" onClick={clearSelection}>{t('Снять выделение', 'Clear selection')}</Action>
        <span className="text-muted-foreground" role="status">{copyStatus}</span>
      </div>}
      {!!items.length && <>
        <div className={`min-w-0 ${display === 'cards' ? 'hidden' : display === 'table' ? 'block' : 'hidden md:block'}`}>
          <DataTable label={t('Устройства', 'Devices')} head={<>
              <th scope="col" className="w-8 rounded-l-lg"><span className="sr-only">{t('Выбор', 'Selection')}</span></th>
              {columns.map(({ label, key }) => {
                const active = !!key && sort.key === key
                const SortIcon = active ? sort.direction === 'asc' ? ArrowUp : ArrowDown : ArrowUpDown
                return <th scope="col" key={label} className={key === 'hostname' ? 'w-[43%] sm:w-[26%]' : key === 'status' ? 'w-[31%] sm:w-[15%]' : 'hidden lg:table-cell'}
                  aria-sort={active ? sort.direction === 'asc' ? 'ascending' : 'descending' : undefined}>
                  {key ? <button type="button" className="inline-flex items-center gap-1 text-left hover:text-primary" onClick={() => changeSort(key)}>
                    {label}<SortIcon className="size-3 shrink-0" aria-hidden />
                  </button> : label}
                </th>
              })}
              <th scope="col" className="w-9 rounded-r-lg"><span className="sr-only">{t('Действия', 'Actions')}</span></th>
            </>}>
            {items.map(device => <tr key={device.id} className={`border-b border-border ${selection.has(device.id) ? 'bg-primary-soft' : 'hover:bg-muted'}`}>
              <td className="px-2 py-3">{rowCheckbox(device)}</td>
              <td className="px-2 py-3"><button type="button" className="break-all text-left font-semibold text-primary hover:underline" onClick={() => onSelect(device.id)}>{device.hostname}</button></td>
              <td className="px-2 py-3"><DeviceStatus device={device} t={t} /></td>
              <td className="hidden lg:table-cell">{device.ips[0] ?? '—'}</td>
              <td className="hidden lg:table-cell">{device.os_version}</td>
              <td className="hidden lg:table-cell">{device.agent_version}</td>
              <td className="hidden lg:table-cell">{stamp(device.last_seen_at)}</td>
              <td className="px-2 py-3"><button type="button" className="rounded-lg p-2 hover:bg-card"
                aria-label={t('Открыть карточку', 'Open device') + ' ' + device.hostname} onClick={() => onSelect(device.id)}><MoreHorizontal className="size-5" aria-hidden /></button></td>
            </tr>)}
          </DataTable>
        </div>
        <ul className={`grid gap-3 sm:grid-cols-2 xl:grid-cols-3 ${display === 'table' ? 'hidden' : display === 'auto' ? 'md:hidden' : ''}`}>
          {items.map(device => <li key={device.id} className="min-w-0">
            <DeviceCard hostname={device.hostname} open={() => onSelect(device.id)} status={<DeviceStatus device={device} t={t} />}
              actions={<>{rowCheckbox(device)}{deviceMenu(device)}</>}>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
              <dt className="text-muted-foreground">IP</dt><dd className="break-all">{device.ips[0] ?? '—'}</dd>
              <dt className="text-muted-foreground">{t('ОС', 'OS')}</dt><dd>{device.os_version}</dd>
              <dt className="text-muted-foreground">{t('Агент', 'Agent')}</dt><dd>{device.agent_version}</dd>
              <dt className="text-muted-foreground">{t('Активность', 'Last seen')}</dt><dd>{stamp(device.last_seen_at)}</dd>
            </dl>
            </DeviceCard>
          </li>)}
        </ul>
      </>}
      {devices.data && (page > 0 || devices.data.total > pageSize) && <div className="mt-4 flex flex-wrap items-center gap-2">
        <Action secondary type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>{t('Предыдущая', 'Previous')}</Action>
        <span className="text-sm text-muted-foreground">{page + 1} / {Math.max(1, Math.ceil(devices.data.total / pageSize))}</span>
        <Action secondary type="button" disabled={(page + 1) * pageSize >= devices.data.total} onClick={() => setPage(page + 1)}>{t('Следующая', 'Next')}</Action>
      </div>}
    </Panel>
  </div>
}

function Computer({ id, session, t, back, inventory, openHistory, onSoftware }: Props & { id: string; back: () => void; inventory: boolean; openHistory: (id: string) => void; onSoftware: (deviceId: string, deviceName: string) => void }) {
  const queryClient = useQueryClient()
  const detail = useQuery({ queryKey: ['device', id], queryFn: () => api<DeviceDetail>(`/devices/${id}`) })
  const [secret, setSecret] = useState<string | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [issuing, setIssuing] = useState(false)
  const [softwareFilter, setSoftwareFilter] = useState('')
  const [softwarePage, setSoftwarePage] = useState(0)
  const [tab, setTab] = useState<'overview' | 'hardware' | 'software' | 'management' | 'events'>(inventory ? 'hardware' : 'overview')
  const [confirmation, setConfirmation] = useState<'revoke' | 'delete' | 'retire' | 'resume' | null>(null)
  const tabs = [
    ['overview', t('Обзор', 'Overview')],
    ['hardware', t('Оборудование', 'Hardware')],
    ['software', t('Программы', 'Software')],
    ['management', t('Управление ПО', 'Software management')],
    ['events', t('События', 'Events')],
  ] as const
  const writable = session.user.role !== 'viewer'
  const action = useMutation({
    mutationFn: (action: 'revoke' | 'delete' | 'retire' | 'resume') => {
      const lifecycle = action === 'retire' || action === 'resume'
      const suffix = lifecycle ? '/' + action : action === 'revoke' ? '/agent' : ''
      return api<void>(`/devices/${id}${suffix}`, { method: lifecycle ? 'POST' : 'DELETE', csrf: session.csrf_token })
    },
    onSuccess: (_, action) => {
      void queryClient.invalidateQueries({ queryKey: ['devices'] })
      void queryClient.invalidateQueries({ queryKey: ['fleet-summary'] })
      void queryClient.invalidateQueries({ queryKey: ['license'] })
      if (action === 'delete') back()
      else {
        setSecret(null)
        void queryClient.invalidateQueries({ queryKey: ['device', id] })
      }
    },
  })

  const diagnostics = useMutation({
    mutationFn: () => api<Blob>(`/devices/${id}/diagnostics/export`, {
      method: 'POST', csrf: session.csrf_token, responseType: 'blob',
    }),
    onSuccess: blob => {
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'deploycore-agent-diagnostics.zip'
      link.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
  })

  async function recover() {
    setIssuing(true)
    setProblem(null)
    try {
      const result = await api<{ token: string }>('/enrollment-tokens', {
        method: 'POST', csrf: session.csrf_token,
        body: { label: `Recovery: ${detail.data?.device.hostname.slice(0, 100) ?? id}`, ttl_minutes: 30, max_uses: 1, device_id: id },
      })
      setSecret(result.token)
      void queryClient.invalidateQueries({ queryKey: ['device', id] })
      void queryClient.invalidateQueries({ queryKey: ['tokens'] })
    } catch (error) {
      setProblem(errorMessage(error, t))
    } finally {
      setIssuing(false)
    }
  }

  const computer = detail.data
  const term = softwareFilter.trim().toLowerCase()
  const programs = computer?.software.filter(program =>
    [program.name, program.version, program.publisher].some(value => value.toLowerCase().includes(term))) ?? []
  const eventNames: Record<string, string> = {
    device_retired: t('Снято с управления', 'Retired'), device_resumed: t('Управление возобновлено', 'Management resumed'),
    registered: t('Зарегистрирован', 'Registered'), reconnected: t('Связь восстановлена', 'Reconnected'),
    inventory_failed: t('Ошибка инвентаризации', 'Inventory refresh failed'),
    name_changed: t('Имя изменено', 'Hostname changed'), inventory_updated: t('Инвентаризация обновлена', 'Inventory updated'),
    recovery_issued: t('Выдан токен восстановления', 'Recovery token issued'),
    agent_revoked: t('Ключ отозван', 'Credential revoked'), agent_recovered: t('Ключ заменён', 'Credential replaced'),
  }
  return <div className="grid gap-5">
    <Action secondary type="button" onClick={back}><ArrowLeft className="size-4" aria-hidden />{t('К списку устройств', 'Back to devices')}</Action>
    <FormError message={detail.error && errorMessage(detail.error, t)} />
    {detail.isPending && <LoadingSkeleton label={t('Загрузка…', 'Loading…')} />}
    {computer && <>
      <Panel>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 flex-wrap items-center gap-3">
            <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-primary-soft text-primary"><Monitor className="size-5" aria-hidden /></div>
            <h2 className="break-all text-xl font-semibold sm:text-2xl">{computer.device.hostname}</h2><DeviceStatus device={computer.device} t={t} />
          </div>
          {writable && <Dropdown label={t('Действия устройства', 'Device actions')} trigger={<MoreHorizontal className="size-5" aria-hidden />}>
            {close => <div className="grid gap-1">
              <button className="rounded-md px-2 py-2 text-left text-sm hover:bg-muted disabled:opacity-50" type="button"
                disabled={issuing || !!secret || action.isPending || computer.device.management_state === 'retired'} onClick={() => { close(); void recover() }}>{t('Выдать токен восстановления', 'Issue recovery token')}</button>
              <button className="rounded-md px-2 py-2 text-left text-sm hover:bg-muted disabled:opacity-50" type="button"
                disabled={action.isPending || issuing || computer.device.agent_revoked}
                onClick={() => { close(); setConfirmation('revoke') }}>{t('Отозвать ключ', 'Revoke credential')}</button>
              {session.user.role === 'super_admin' && <button type="button" className="rounded-md px-2 py-2 text-left text-sm hover:bg-muted"
                disabled={action.isPending || issuing} onClick={() => {
                  close(); setConfirmation(computer.device.management_state === 'retired' ? 'resume' : 'retire')
                }}>{computer.device.management_state === 'retired' ? t('Возобновить управление', 'Resume management') : t('Снять с управления', 'Retire device')}</button>}
              <button className="rounded-md px-2 py-2 text-left text-sm text-danger hover:bg-danger-soft disabled:opacity-50" type="button"
                disabled={action.isPending || issuing} onClick={() => { close(); setConfirmation('delete') }}>{t('Удалить устройство', 'Delete device')}</button>
            </div>}
          </Dropdown>}
        </div>
        <div role="group" aria-label={t('Разделы карточки', 'Device card sections')} className="mt-4 flex flex-wrap gap-1 border-t border-border pt-3">
          {tabs.map(([id, label]) => <button type="button" key={id} aria-pressed={tab === id} onClick={() => setTab(id)}
            className={`rounded-md px-3 py-2 text-sm font-medium hover:bg-muted ${tab === id ? 'bg-primary-soft text-primary' : 'text-muted-foreground'}`}>
            {label}
          </button>)}
        </div>
        {secret && <div className="mt-4 grid gap-2">
          <p className="text-sm">{t('На прежней машине используйте recover. При новой установке укажите --device-id с ID этой карточки.', 'Use recover on the existing machine. On a fresh install, pass this device ID with --device-id.')}</p>
          <SecretBox value={secret} t={t} close={() => setSecret(null)} />
        </div>}
        <FormError message={problem || (action.error && errorMessage(action.error, t))} />
      </Panel>
      {confirmation && <ConfirmDialog
        title={{
          revoke: t('Отозвать ключ?', 'Revoke the credential?'), delete: t('Удалить устройство?', 'Delete the device?'),
          retire: t('Снять устройство с управления?', 'Retire this device?'), resume: t('Возобновить управление?', 'Resume management?'),
        }[confirmation]}
        labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Подтвердить', 'Confirm') }}
        description={confirmation === 'revoke'
          ? t(`Агент на ${computer.device.hostname} потеряет доступ до восстановления ключа.`, `The agent on ${computer.device.hostname} loses access until its credential is recovered.`)
          : confirmation === 'retire' ? t('Место освободится, ключ будет отозван, а инвентарь и история сохранятся.', 'This releases the slot and revokes the credential while keeping inventory and history.')
          : confirmation === 'resume' ? t('Устройство займёт место. Для подключения выдайте токен восстановления.', 'The device occupies a slot. Issue a recovery token to reconnect it.')
          : t(`Устройство ${computer.device.hostname} и его инвентарь будут удалены.`, `Device ${computer.device.hostname} and its inventory will be deleted.`)}
        close={() => setConfirmation(null)} confirm={() => { action.mutate(confirmation); setConfirmation(null) }} />}
      {tab === 'overview' && <Panel>
        <h2 className="text-base font-semibold">{t('Сведения об устройстве', 'Device information')}</h2>
        <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2">
          {[
            ['ID', id], ['FQDN', computer.device.fqdn],
            [computer.device.domain_joined ? t('Домен', 'Domain') : t('Рабочая группа', 'Workgroup'), computer.device.network_name],
            ['IP', computer.device.ips.join(', ')], [t('ОС', 'OS'), computer.device.os_version],
            [t('Версия агента', 'Agent version'), computer.device.agent_version],
            [t('Последняя активность', 'Last seen'), stamp(computer.device.last_seen_at)],
            [t('Время работы, мин', 'Uptime, min'), String(Math.floor(computer.device.uptime_seconds / 60))],
          ].map(([label, value]) => <div key={label}><dt className="text-muted-foreground">{label}</dt><dd className="break-all">{value || '—'}</dd></div>)}
        </dl>
      </Panel>}
      {tab === 'hardware' && <Panel>
        <h2 className="mb-3 text-lg font-semibold">{t('Аппаратные характеристики', 'Hardware inventory')}</h2>
        {computer.inventory ? <div className="grid gap-3 break-words text-sm">
          <p className="text-muted-foreground">{t('Получено', 'Received')} <time>{stamp(computer.inventory.collected_at)}</time></p>
          <p>{[computer.inventory.hardware.manufacturer, computer.inventory.hardware.model].filter(Boolean).join(' ') || '—'}</p>
          <p>{computer.inventory.hardware.os.version} · {t('сборка', 'build')} {computer.inventory.hardware.os.build} · {computer.inventory.hardware.os.architecture}</p>
          {computer.inventory.hardware.cpus.map((cpu, index) => <p key={index}>{cpu.model} · {cpu.cores} {t('ядер', 'cores')} · {cpu.threads} {t('потоков', 'threads')}</p>)}
          <p>RAM · {gib(computer.inventory.hardware.ram_bytes)} GiB</p>
          <ul>{computer.inventory.hardware.disks.map(disk => <li key={disk.letter}>{[disk.letter, disk.label, disk.filesystem].filter(Boolean).join(' · ')} · {gib(disk.free_bytes)} / {gib(disk.size_bytes)} GiB {t('свободно', 'free')}</li>)}</ul>
          <ul>{computer.inventory.hardware.interfaces.map((nic, index) => <li key={index}>{nic.name}{nic.mac && ` · ${nic.mac}`} · {nic.ips.join(', ') || '—'}</li>)}</ul>
        </div> : <EmptyState title={t('Снимок ещё не получен', 'Inventory has not arrived yet')} />}
      </Panel>}
      {tab === 'software' && <Panel>
        <h2 className="mb-3 text-lg font-semibold">{t('Установленные программы', 'Installed software')} · {computer.software.length}</h2>
        {!!computer.software.length && <Field label={t('Поиск по программам', 'Search software')} value={softwareFilter} onChange={event => { setSoftwarePage(0); setSoftwareFilter(event.target.value) }} />}
        {computer.software.length === 0 && <p className="text-sm text-muted-foreground">{computer.inventory
          ? t('Агент не нашёл программ в реестре.', 'The agent found no software in the registry.')
          : t('Агент ещё не прислал инвентаризацию.', 'The agent has not sent an inventory yet.')}</p>}
        {!!computer.software.length && !programs.length && <EmptyState title={t('Программы по запросу не найдены', 'No matching software')} />}
        <ul className="mt-3 text-sm">
          {programs.slice(softwarePage * pageSize, (softwarePage + 1) * pageSize).map(program =>
            <li key={JSON.stringify(program)} className="grid gap-1 break-words border-t border-border py-2 sm:grid-cols-3">
              <span>{program.name}</span><span className="text-muted-foreground">{program.version}</span><span className="text-muted-foreground">{program.publisher}</span>
            </li>)}
        </ul>
        {programs.length > pageSize && <div className="mt-3 flex flex-wrap gap-2">
          <Action secondary disabled={!softwarePage} onClick={() => setSoftwarePage(softwarePage - 1)}>{t('Предыдущая', 'Previous')}</Action>
          <Action secondary disabled={(softwarePage + 1) * pageSize >= programs.length} onClick={() => setSoftwarePage(softwarePage + 1)}>{t('Следующая', 'Next')}</Action>
        </div>}
      </Panel>}
      {tab === 'management' && <Panel>
        <SectionTitle title={t('Управление ПО', 'Software management')}
          actions={<Action secondary onClick={() => openHistory(id)}>{t('История развёртываний', 'Deployment history')}</Action>} />
        {writable && !computer.device.agent_revoked && computer.device.management_state !== 'retired'
          ? <Action onClick={() => onSoftware(id, computer.device.hostname)}>{t('Создать задание для этого ПК', 'Create a job for this computer')}</Action>
          : <EmptyState title={t('Создание заданий недоступно', 'Job creation unavailable')} />}
      </Panel>}
      {tab === 'events' && <Panel>
        <SectionTitle title={t('История событий', 'Event history')}
          actions={writable && <Action secondary disabled={diagnostics.isPending} onClick={() => diagnostics.mutate()}>
            <ArrowDownToLine className="size-4" aria-hidden />
            {t('Скачать сводку диагностики', 'Download diagnostic summary')}
          </Action>} />
        <FormError message={diagnostics.error && errorMessage(diagnostics.error, t)} />
        {computer.events.length ? <ActivityFeed items={computer.events.map(event => ({
          key: event.id, title: eventNames[event.action] ?? event.action, time: event.created_at,
        }))} /> : <EmptyState title={t('Событий пока нет', 'No events yet')} />}
      </Panel>}
    </>}
  </div>
}

function CopyCommand({ title, value, t }: { title: string; value: string; t: Translate }) {
  const [copied, setCopied] = useState(false)
  return <div className="grid min-w-0 gap-2">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-sm font-medium">{title}</span>
      <Action type="button" secondary onClick={() => void navigator.clipboard.writeText(value).then(
        () => setCopied(true), () => setCopied(false),
      )}>{copied ? t('Скопировано', 'Copied') : t('Копировать', 'Copy')}</Action>
    </div>
    <pre className="whitespace-pre-wrap break-all rounded-lg bg-background p-3 text-sm"><code>{value}</code></pre>
  </div>
}

export function AgentInstallPage({ session, t, server, configuredAddress }: Props & { server: string; configuredAddress: boolean }) {
  const client = useQueryClient()
  const [secret, setSecret] = useState<string | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [offset, setOffset] = useState(0)
  const tokens = useQuery({ queryKey: ['tokens', offset], queryFn: () => api<Token[]>(`/enrollment-tokens?offset=${offset}`) })
  const revoke = useMutation({
    mutationFn: (id: string) => api<void>(`/enrollment-tokens/${id}`, { method: 'DELETE', csrf: session.csrf_token }),
    onSuccess: () => { setSecret(null); void client.invalidateQueries({ queryKey: ['tokens'] }) },
  })
  const origin = server.replace(/\/$/, '')
  const sameOrigin = origin === window.location.origin && window.location.protocol === 'https:'
  const check = useQuery({
    queryKey: ['agent-readiness', origin], enabled: sameOrigin, refetchInterval: pollEvery(30_000),
    queryFn: async ({ signal }) => {
      const result = await fetch('/api/health/ready', { cache: 'no-store', signal, redirect: 'error' })
      if (!result.ok || (await result.json()).status !== 'ok') throw new Error('not ready')
      return true
    },
  })

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    setBusy(true)
    setProblem(null)
    try {
      const body = { label: fields.get('label'), ttl_minutes: Number(fields.get('ttl_minutes')), max_uses: Number(fields.get('max_uses')) }
      const button = (event.nativeEvent as SubmitEvent).submitter
      if (button instanceof HTMLButtonElement && (button.value === 'msi' || button.value === 'rollout')) {
        const rollout = button.value === 'rollout'
        const ca = fields.get('ca')
        if (ca instanceof File && ca.size > 65536) {
          setProblem(t('PEM-файл превышает 64 КиБ.', 'The PEM file exceeds 64 KiB.'))
          return
        }
        const packageFile = await api<Blob>('/agent-packages', {
          method: 'POST', csrf: session.csrf_token, responseType: 'blob',
          body: { ...body, rollout, ca: ca instanceof File ? await ca.text() : '' },
        })
        const url = URL.createObjectURL(packageFile)
        const link = document.createElement('a')
        link.href = url
        link.download = rollout ? 'deploycore-agent-rollout.zip' : 'deploycore-managed-agent.msi'
        document.body.append(link)
        link.click()
        link.remove()
        window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      } else {
        const issued = await api<{ token: string }>('/enrollment-tokens', { method: 'POST', csrf: session.csrf_token, body })
        setSecret(issued.token)
      }
      setOffset(0)
      void client.invalidateQueries({ queryKey: ['tokens'] })
    } catch (error) {
      setProblem(errorMessage(error, t))
    } finally {
      setBusy(false)
    }
  }

  const quotedOrigin = "'" + origin.replaceAll("'", "''") + "'"
  return <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
    <Panel>
      <SectionTitle title={t('Установщик Windows x64', 'Windows x64 installer')} />
      <p className="mb-2 break-all text-sm">{t('Адрес сервера', 'Server address')} <code className="ml-2 text-primary">{origin}</code></p>
      <div className="my-3 flex flex-wrap items-center gap-3 text-sm text-primary">
        <a className="inline-flex items-center gap-2 rounded-xl bg-accent px-3 py-2 font-semibold text-primary-foreground hover:bg-primary-hover" href="/assets/agent/deploycore-agent.msi" download><ArrowDownToLine className="size-4" aria-hidden />{t('MSI с ручной настройкой', 'MSI with manual setup')}</a>
        <a href="/assets/agent/deploycore-agent.exe" download>{t('Скачать Windows Agent', 'Download Windows Agent')}</a>
        <a href="/assets/agent/SHA256SUMS" download>SHA256SUMS</a>
        <a href="/assets/agent/upgrade-agent.ps1" download>{t('Сценарий обновления службы', 'Service migration script')}</a>
        <a href="/assets/agent/build.json" download>{t('Сведения о сборке', 'Build information')}</a>
      </div>
      <p className="my-4 text-sm text-foreground">{t('После установки MSI откройте DeployCore Agent Setup в меню «Пуск». Введите адрес сервера и токен. Скачанный EXE также открывает мастер. Для команд откройте PowerShell от имени администратора в папке с EXE.', 'After installing the MSI, open DeployCore Agent Setup from Start. Enter the server and token. The downloaded EXE also opens the wizard. For commands, open PowerShell as administrator in the folder containing the EXE.')}</p>
      <div className="grid min-w-0 gap-4">
        <CopyCommand t={t} title={t('Проверить HTTPS', 'Check HTTPS')} value={`.\\deploycore-agent.exe check --server ${quotedOrigin}`} />
        <CopyCommand t={t} title={t('Установить службу', 'Install service')} value={`[Net.NetworkCredential]::new('', (Read-Host 'Enrollment token' -AsSecureString)).Password | .\\deploycore-agent.exe install --server ${quotedOrigin}`} />
        <CopyCommand t={t} title={t('Удалить службу', 'Uninstall service')} value={`.\\deploycore-agent.exe uninstall`} />
      </div>
      <p className="mt-4 text-sm text-muted-foreground">{t('Для корпоративного CA установите доверенный корневой сертификат компьютера или добавьте --ca с путём к PEM-файлу в команды проверки и установки.', 'For a private CA, trust the root in the machine store or add --ca with the PEM file path to the check and install commands.')}</p>
      {sameOrigin && <div className="mt-3">
        <Action secondary type="button" onClick={() => void check.refetch()} disabled={check.isFetching}>{t('Повторить проверку из браузера', 'Check again from browser')}</Action>
        {check.isSuccess && <p role="status" className="mt-2 text-success">{t('Текущий сервер отвечает по HTTPS.', 'The current server responds over HTTPS.')}</p>}
        <FormError message={check.error && t('Проверка HTTPS или готовности сервера не прошла.', 'HTTPS or server readiness check failed.')} />
      </div>}
    </Panel>
    <div className="grid min-w-0 gap-4"><Panel>
      <SectionTitle title={t('Готовый MSI и токены', 'Configured MSI and tokens')} />
      <p className="mb-3 text-sm">{t('Готовый MSI устанавливает службу с сохранённым адресом и временным токеном. Передавайте файл только тем, кому разрешена регистрация компьютера.',
        'The configured MSI installs the service with the saved address and a temporary token. Share it only with people authorized to enroll a computer.')}</p>
      {!configuredAddress && <p className="mb-3 text-sm">{t('Сначала задайте адрес для агентов в настройках экземпляра.', 'Set the agent address in instance settings first.')}</p>}
      <form className="grid gap-3" onSubmit={submit}>
        <fieldset className="grid gap-3 sm:grid-cols-2" disabled={busy || !!secret}>
          <Field name="label" label={t('Название', 'Name')} required maxLength={120} />
          <Field name="ttl_minutes" label={t('Срок, мин', 'Lifetime, min')} required type="number" min={1} max={10080} defaultValue={60} />
          <Field name="max_uses" label={t('Лимит регистраций', 'Registration limit')} required type="number" min={1} max={100} defaultValue={1} />
          <Field name="ca" type="file" accept=".pem,.crt" label={t('Доверенный CA для MSI', 'Trusted CA for MSI')}
            hint={t('Необязательно, если Windows уже доверяет сертификату сервера.', 'Optional if Windows already trusts the server certificate.')} />
        </fieldset>
        <FormError message={problem} />
        <div className="flex flex-wrap gap-2">
          <Action type="submit" value="msi" disabled={busy || !!secret || !configuredAddress}>{t('Скачать готовый MSI', 'Download configured MSI')}</Action>
          <Action type="submit" value="rollout" secondary disabled={busy || !!secret || !configuredAddress}>
            {t('Скачать комплект обновления', 'Download upgrade bundle')}
          </Action>
          <Action type="submit" secondary disabled={busy || !!secret}>{t('Создать токен', 'Create token')}</Action>
        </div>
      </form>
      {secret && <div className="mt-4"><SecretBox value={secret} t={t} close={() => setSecret(null)} /></div>}
    </Panel>
    <Panel>
      <SectionTitle title={t('Выданные токены', 'Issued tokens')} />
      {tokens.isPending && <LoadingSkeleton label={t('Загрузка токенов', 'Loading tokens')} />}
      <FormError message={(tokens.error || revoke.error) && errorMessage(tokens.error || revoke.error, t)} />
      {tokens.data?.length === 0 && <EmptyState title={t('Токенов пока нет', 'No tokens yet')} />}
      <ul>{tokens.data?.map(token => <li key={token.id} className="flex flex-wrap items-center justify-between gap-3 border-t border-border py-3 text-sm">
        <div className="min-w-0">
          <p className="break-all font-medium">{token.label}</p>
          <p className="text-muted-foreground">{token.uses}/{token.max_uses} · <time>{stamp(token.expires_at)}</time>{token.revoked_at && ` · ${t('отозван', 'revoked')}`}</p>
        </div>
        {!token.revoked_at && new Date(token.expires_at).getTime() > Date.now() && <Action secondary type="button" disabled={revoke.isPending} onClick={() => revoke.mutate(token.id)}>{t('Отозвать', 'Revoke')}</Action>}
      </li>)}</ul>
      <div className="mt-3 flex flex-wrap gap-3">
        {offset > 0 && <Action secondary type="button" onClick={() => setOffset(offset - 100)}>{t('Предыдущая', 'Previous')}</Action>}
        {tokens.data?.length === 100 && <Action secondary type="button" onClick={() => setOffset(offset + 100)}>{t('Следующая', 'Next')}</Action>}
      </div>
    </Panel></div>
  </div>
}
