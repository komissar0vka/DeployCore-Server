import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { ListTodo, Plus } from 'lucide-react'
import { useRef, useState, type FormEvent } from 'react'
import type { JobScope } from './console-shell'
import { api, pollEvery, type Session } from './api'
import { useDeviceGroups } from './groups'
import { Dialog } from './components/ui/dialog'
import { ActivityFeed, ConfirmDialog, EmptyState, LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, Field, FormError, Panel, detectionLabel, errorMessage, type Translate } from './ui'

type Operation = 'install' | 'uninstall'
type TargetState = 'queued' | 'leased' | 'running' | 'not_executed' | 'cancelled' | 'failed' | 'succeeded' | 'already_installed' | 'already_absent' | 'reboot_required' | 'awaiting_reboot' | 'unknown'
interface Job {
  id: string; package_name: string; version: string; operation: Operation; mode: 'transport_only' | 'execute_v1'; created_at: string
  not_before: string | null
  counts: Partial<Record<TargetState, number>>
}
interface Target {
  id: string; hostname: string; state: TargetState; cancel_requested: boolean
  retry_requires_admin?: boolean; attempt: number | null; lease_expires_at: string | null; recovery_required: boolean
  started_at?: string | null; process_started?: boolean | null; detection?: string | null
  reboot_detection?: string | null; reboot_deadline?: string | null; reboot_finished_at?: string | null; reboot_diagnostic?: string | null
  stage?: string; exit_code?: number | null; diagnostic?: string; output_bytes?: number | null
}
interface Entry { id: number; target_id: string | null; attempt_number?: number | null; action: string; created_at: string }
interface Device { id: string; hostname: string; online: boolean; agent_revoked: boolean; agent_version: string }
interface Product { id: string; name: string }
interface Version { revision: number; id: string; version: string; architecture: string; approved_at: string | null; install_args: string[]; uninstall_args: string[] | null; installer: string; detection: { kind: string }; timeout_seconds: number }
interface Props { session: Session; t: Translate }
export interface DeploymentPreset { programs?: Product[]; packageId?: string; versionId?: string; productName?: string; deviceId?: string; deviceName?: string }
interface Input { mode: 'transport_only' | 'execute_v1'; version_id: string; operation: Operation; device_ids: string[]; request_id: string; not_before: string | null }
type BatchInput = Omit<Input, 'operation' | 'version_id'> & { version_ids: string[] }
const pageSize = 25

function compatible(version: string, minimumPatch = 4) {
  if (!/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(version)) return false
  const [major, minor, patch] = version.split('.').map(Number)
  return major > 0 || minor > 3 || (minor === 3 && patch >= minimumPatch)
}

function stateLabel(state: TargetState, t: Translate) {
  return {
    queued: t('Ожидает подключения', 'Waiting for connection'), leased: t('Передаётся агенту', 'Sending to agent'), running: t('Выполняется', 'In progress'),
    cancelled: t('Отменено', 'Cancelled'), not_executed: t('Без запуска', 'Not executed'),
    failed: t('Ошибка', 'Failed'), succeeded: t('Успешно', 'Succeeded'),
    already_installed: t('Уже установлено', 'Already installed'), already_absent: t('Уже отсутствует', 'Already absent'),
    reboot_required: t('Требуется перезагрузка', 'Restart required'),
    awaiting_reboot: t('Ожидается проверка после перезагрузки', 'Awaiting detection after restart'), unknown: t('Исход неизвестен', 'Unknown outcome'),
  }[state]
}

function diagnosis(code: string, t: Translate) {
  const labels: Record<string, string> = {
    detection_failed: t('Проверка обнаружения недоступна', 'Detection could not complete'),
    detection_mismatch: t('Обнаруженное состояние не совпадает с ожидаемым', 'Detected state differs from the expected state'),
    reboot_timeout: t('Срок проверки после перезагрузки истёк', 'Post-restart verification expired'),
    download_failed: t('Не удалось скачать установщик', 'Installer download failed'),
    hash_mismatch: t('Размер или SHA-256 установщика не совпадает', 'Installer size or SHA-256 mismatch'),
    insufficient_space: t('Недостаточно места на устройстве', 'Insufficient disk space'),
    installer_error: t('Установщик вернул недопустимый код', 'Installer returned an unexpected exit code'),
    timeout: t('Истёк таймаут запуска', 'Installer timed out'),
    interrupted: t('Попытка прервалась', 'Attempt was interrupted'),
    platform_unsupported: t('Версия или архитектура Windows не поддерживается', 'Unsupported Windows build or architecture'),
    manifest_invalid: t('Не удалось получить допустимый манифест', 'Could not obtain a valid manifest'),
    process_error: t('Ошибка при запуске или наблюдении за процессом', 'Process launch or monitoring failed'),
    operator_resolved: t('Исход обработан вручную', 'Outcome resolved manually'),
    device_removed: t('Устройство удалено', 'Device removed'),
    device_retired: t('Устройство снято с управления', 'Device retired'),
  }
  return labels[code] ?? code
}

function operationLabel(operation: Operation, t: Translate) {
  return operation === 'install' ? t('Установка', 'Install') : t('Удаление', 'Uninstall')
}

function JobProgress({ job, t }: { job: Job; t: Translate }) {
  const total = Object.values(job.counts).reduce((sum, count) => sum + count, 0)
  const complete = total - (job.counts.queued ?? 0) - (job.counts.leased ?? 0) - (job.counts.running ?? 0) - (job.counts.unknown ?? 0) - (job.counts.awaiting_reboot ?? 0)
  return <div className="grid gap-1.5 text-xs text-muted-foreground">
    {job.not_before && new Date(job.not_before).getTime() > Date.now() &&
      <span>{t('Запланировано на', 'Scheduled for')} {new Date(job.not_before).toLocaleString(t('ru', 'en'))}</span>}
    <span>{t('Завершено целей', 'Targets finished')}: {complete}/{total}</span>
    <progress className="h-1.5 w-full max-w-xs accent-primary" value={complete} max={Math.max(1, total)}
      aria-label={t('Прогресс обработки', 'Processing progress')} />
    <div className="flex flex-wrap gap-2">{Object.entries(job.counts).map(([state, count]) =>
      <span key={state}>{stateLabel(state as TargetState, t)}: {count}</span>)}</div>
  </div>
}

function NewJob({ session, t, close, created, preset }: Props & { close: () => void; created: (id: string) => void; preset?: DeploymentPreset }) {
  const batchPrograms = preset?.programs ?? []
  const batchMode = batchPrograms.length > 1
  const [batchVersions, setBatchVersions] = useState<Record<string, string>>({})
  const [packageTerm, setPackageTerm] = useState('')
  const [packageId, setPackageId] = useState(preset?.packageId ?? '')
  const [versionId, setVersionId] = useState(preset?.versionId ?? '')
  const [operation, setOperation] = useState<Operation>('install')
  const [mode, setMode] = useState<Input['mode']>('execute_v1')
  const [confirm, setConfirm] = useState(false)
  const [schedule, setSchedule] = useState('')
  const [term, setTerm] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState(() => new Map<string, { hostname: string; agent_version?: string }>(preset?.deviceId ? [[preset.deviceId, { hostname: preset.deviceName ?? preset.deviceId }]] : []))
  const submission = useRef<{ fingerprint: string; requestId: string } | null>(null)

  const groups = useDeviceGroups()
  const [groupError, setGroupError] = useState('')
  const products = useQuery({
    queryKey: ['job-products', packageTerm], enabled: !batchMode,
    queryFn: () => api<{ items: Product[] }>(`/packages?${new URLSearchParams({ q: packageTerm, limit: '25' })}`),
  })
  const versions = useQuery({
    queryKey: ['job-versions', packageId], enabled: Boolean(packageId),
    queryFn: () => api<{ versions: Version[] }>('/packages/' + packageId),
  })
  const batchQueries = useQueries({ queries: batchPrograms.map(product => ({
    queryKey: ['job-versions', product.id],
    queryFn: () => api<{ versions: Version[] }>('/packages/' + product.id),
  })) })
  const batchChoices = batchPrograms.map((product, index) => {
    const list = (batchQueries[index].data?.versions ?? []).filter(version => version.approved_at)
    const chosen = list.find(version => version.id === batchVersions[product.id]) ?? (list.length === 1 ? list[0] : undefined)
    return { product, list, chosen }
  })
  const computers = useQuery({
    queryKey: ['job-devices', term, offset],
    queryFn: () => api<{ items: Device[]; total: number }>(`/devices?${new URLSearchParams({ q: term, offset: String(offset), limit: String(pageSize) })}`),
  })
  const eligible = (versions.data?.versions ?? []).filter(version => version.approved_at && (operation === 'install' || version.uninstall_args !== null))
  const chosen = eligible.find(version => version.id === versionId) ?? (eligible.length === 1 ? eligible[0] : undefined)
  const plans = batchMode ? batchChoices.flatMap(choice => choice.chosen ? [choice.chosen] : []) : chosen ? [chosen] : []
  const minimumPatch = plans.some(version => version.installer === 'portable') ? 8 : plans.some(version => version.detection.kind === 'all' || version.detection.kind === 'any') ? 5 : 4
  const compatibleSelection = mode !== 'execute_v1' || [...selected.values()].every(device => !device.agent_version || compatible(device.agent_version, minimumPatch))
  const canSubmit = compatibleSelection && plans.length === (batchMode ? batchPrograms.length : 1) && selected.size > 0 && (mode !== 'execute_v1' || operation !== 'uninstall' || session.user.role === 'super_admin')
  const mutation = useMutation({
    mutationFn: (body: Input | BatchInput) => 'version_ids' in body
      ? api<{ items: Job[] }>('/deployments/batch', { method: 'POST', body, csrf: session.csrf_token }).then(result => result.items[0])
      : api<Job>('/deployments', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: job => created(job.id),
  })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canSubmit || mutation.isPending) return
    if (mode === 'execute_v1') setConfirm(true)
    else submitJob()
  }

  function submitJob() {
    const targets = { mode, device_ids: [...selected.keys()].sort(),
      not_before: schedule ? new Date(schedule).toISOString() : null }
    const payload = batchMode
      ? { ...targets, version_ids: plans.map(version => version.id) }
      : { ...targets, version_id: chosen?.id ?? '', operation }
    const fingerprint = JSON.stringify(payload)
    if (submission.current?.fingerprint !== fingerprint) {
      submission.current = { fingerprint, requestId: crypto.randomUUID() }
    }
    mutation.mutate({ ...payload, request_id: submission.current.requestId })
  }

  function toggle(device: Device) {
    setSelected(current => {
      const next = new Map(current)
      if (next.has(device.id)) next.delete(device.id)
      else if (next.size < 100) next.set(device.id, device)
      return next
    })
  }

  return <Dialog title={confirm ? t('Подтвердите запуск', 'Confirm execution') : t('Новое задание', 'New job')} closeLabel={t('Закрыть', 'Close')} close={close}>
    {confirm ? <div className="grid gap-3 text-sm">
      {batchMode ? <ul className="list-disc pl-5">{batchChoices.map(({ product, chosen }) =>
        <li key={product.id}>{product.name} · {chosen?.version}</li>)}</ul>
        : <p>{operationLabel(operation, t)} · {chosen?.version} · {chosen?.architecture}</p>}
      <p className="break-words">{[...selected.values()].map(device => device.hostname).join(', ')}</p>
      {schedule && <p>{t('Запуск после', 'Run after')} {new Date(schedule).toLocaleString(t('ru', 'en'))}</p>}
      {!batchMode && <details>
        <summary className="cursor-pointer text-muted-foreground">{t('Командная строка', 'Command line')}</summary>
        <code className="break-all">{JSON.stringify(operation === 'install' ? chosen?.install_args : chosen?.uninstall_args)}</code>
      </details>}
      <FormError message={mutation.error && errorMessage(mutation.error, t)} />
      <div className="flex flex-wrap gap-2">
        <Action secondary disabled={mutation.isPending} onClick={() => setConfirm(false)}>{t('Назад', 'Back')}</Action>
        <Action disabled={mutation.isPending} onClick={submitJob}>{t('Подтвердить запуск', 'Confirm execution')}</Action>
      </div>
    </div> : <form className="grid gap-3" onSubmit={submit}>
      <details className="rounded-lg border border-border p-3">
        <summary className="cursor-pointer text-sm font-medium">{t('Дополнительные параметры', 'Advanced options')}</summary>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
      <label className="grid gap-2 text-sm">{t('Режим', 'Mode')}
        <select className="input" aria-label={t('Режим', 'Mode')} value={mode} onChange={event => {
          setMode(event.target.value as Input['mode']); setOperation('install'); setSelected(new Map())
        }}>
          <option value="execute_v1">{t('Выполнение на Windows', 'Execute on Windows')}</option>
          <option value="transport_only">{t('Проверка транспорта', 'Transport test')}</option>
        </select>
      </label>
      {!batchMode && <label className="grid gap-2 text-sm">{t('Операция', 'Operation')}
        <select aria-label={t('Операция', 'Operation')} className="input" value={operation} onChange={event => {
          setOperation(event.target.value as Operation); setVersionId('')
        }}>
          <option value="install">{operationLabel('install', t)}</option>
          <option value="uninstall" disabled={mode === 'execute_v1' && session.user.role !== 'super_admin'}>{operationLabel('uninstall', t)}</option>
        </select>
      </label>}
          <Field label={t('Запустить после', 'Run after')} hint={t('Время на этом компьютере', 'This computer’s local time')}
            type="datetime-local" value={schedule} onChange={event => setSchedule(event.target.value)} />
        </div>
      </details>
      {batchMode ? <div className="grid gap-3">{batchChoices.map(({ product, list, chosen }, index) =>
        <label className="grid gap-2 text-sm" key={product.id}>{product.name}
          <select className="input" aria-label={product.name} disabled={!list.length} value={chosen?.id ?? ''}
            onChange={event => setBatchVersions(current => ({ ...current, [product.id]: event.target.value }))}>
            <option value="">{t('Выбери утверждённую версию', 'Select an approved version')}</option>
            {list.map(version => <option key={version.id} value={version.id}>{version.version} · {version.architecture}</option>)}
          </select>
          {!list.length && !batchQueries[index].isPending && <span className="text-muted-foreground">
            {t('Утверждённых версий нет.', 'No approved versions.')}</span>}
        </label>
      )}</div> : <>
      <Field label={t('Поиск программы', 'Search programs')} maxLength={160} value={packageTerm} onChange={event => {
        setPackageTerm(event.target.value); setPackageId(''); setVersionId('')
      }} />
      <label className="grid gap-2 text-sm">{t('Программа', 'Program')}
        <select aria-label={t('Программа', 'Program')} className="input" required value={packageId} onChange={event => {
          setPackageId(event.target.value); setVersionId('')
        }}>
          <option value="">{t('Выберите программу', 'Select a program')}</option>
          {packageId && !products.data?.items.some(product => product.id === packageId) &&
            <option value={packageId}>{preset?.productName ?? packageId}</option>}
          {products.data?.items.map(product => <option key={product.id} value={product.id}>{product.name}</option>)}
        </select>
      </label>
      <label className="grid gap-2 text-sm">{t('Утверждённая версия', 'Approved version')}
        <select aria-label={t('Утверждённая версия', 'Approved version')} className="input" required disabled={!eligible.length}
          value={chosen?.id ?? ''} onChange={event => setVersionId(event.target.value)}>
          <option value="">{t('Выберите версию', 'Select a version')}</option>
          {eligible.map(version => <option key={version.id} value={version.id}>{version.version}{version.revision > 1 ? ` · ${t('ревизия', 'revision')} ${version.revision}` : ''} · {version.architecture}</option>)}
        </select>
      </label>
      {versions.data && !eligible.length && <p className="text-sm text-muted-foreground">
        {t('Для этой операции нет утверждённых версий.', 'There are no approved versions for this operation.')}
      </p>}
      </>}
      {!compatibleSelection && <FormError message={t('Уберите устройства с несовместимой версией агента.', 'Deselect devices running an incompatible agent version.')} />}
      {!!groups.data?.length && <label className="grid gap-2 text-sm">{t('Добавить группу устройств', 'Add a device group')}
        <select className="input" aria-label={t('Добавить группу устройств', 'Add a device group')} value=""
          onChange={event => {
            const group = groups.data.find(item => item.id === event.target.value)
            if (!group) return
            const picked = new Map(selected)
            group.devices.forEach(device => picked.set(device.id, device))
            if (picked.size > 100) {
              setGroupError(t('В одном задании можно выбрать до 100 устройств.', 'Select up to 100 devices per job.'))
              return
            }
            setGroupError('')
            setSelected(picked)
          }}>
          <option value="">{t('Выбери группу', 'Select a group')}</option>
          {groups.data.map(group => <option key={group.id} value={group.id} disabled={!group.devices.length}>
            {group.name} · {group.devices.length}
          </option>)}
        </select>
      </label>}
      <FormError message={groupError || (groups.error && errorMessage(groups.error, t))} />
      <Field label={t('Имя, FQDN или IP устройства', 'Device hostname, FQDN or IP')} maxLength={120}
        value={term} onChange={event => { setTerm(event.target.value); setOffset(0) }} />
      {computers.isPending && <LoadingSkeleton label={t('Загрузка устройств', 'Loading devices')} />}
      <ul className="max-h-36 overflow-y-auto rounded-lg border border-border p-2 text-sm">
        {computers.data?.items.map(device => <li key={device.id}>
          <label className="flex items-center gap-2 py-1">
            <input type="checkbox" checked={selected.has(device.id)} disabled={device.agent_revoked || (mode === 'execute_v1' && !compatible(device.agent_version, minimumPatch) && !selected.has(device.id)) || (selected.size === 100 && !selected.has(device.id))}
              onChange={() => toggle(device)} />
            <span className="min-w-0 grow break-all">{device.hostname}</span>
            <span className="text-xs text-muted-foreground">{device.agent_revoked ? t('Отозван', 'Revoked') : device.online ? t('Онлайн', 'Online') : t('Офлайн', 'Offline')}</span>
          </label>
        </li>)}
        {computers.data?.items.length === 0 && <li className="py-1 text-muted-foreground">{t('Устройства не найдены', 'No devices found')}</li>}
      </ul>
      {(offset > 0 || (computers.data?.total ?? 0) > pageSize) && <div className="flex flex-wrap gap-2">
        <Action secondary disabled={offset === 0} onClick={() => setOffset(offset - pageSize)}>{t('Предыдущая', 'Previous')}</Action>
        <Action secondary disabled={offset + pageSize >= (computers.data?.total ?? 0)} onClick={() => setOffset(offset + pageSize)}>{t('Следующая', 'Next')}</Action>
      </div>}
      <p className="text-sm text-muted-foreground">{t('Выбрано устройств', 'Selected devices')}: {selected.size}/100</p>
      {selected.size > 0 && <p className="max-h-16 overflow-y-auto break-words text-xs text-muted-foreground">
        {[...selected.values()].map(device => device.hostname).join(', ')}
      </p>}
      <FormError message={(products.error || versions.error || computers.error || mutation.error) &&
        errorMessage(products.error || versions.error || computers.error || mutation.error, t)} />
      <Action type="submit" disabled={!canSubmit || mutation.isPending}>{batchMode ? t('Создать задания', 'Create jobs') : t('Создать задание', 'Create job')}</Action>
    </form>}
  </Dialog>
}

function JobDetails({ session, t, id, back }: Props & { id: string; back: () => void }) {
  const path = '/deployments/' + id
  const query = useQuery({ queryKey: ['deployments', id], queryFn: () => api<Job & { targets: Target[] }>(path), refetchInterval: pollEvery(5000) })
  const [before, setBefore] = useState<number>()
  const [eventTarget, setEventTarget] = useState('')
  const events = useQuery({
    queryKey: ['deployment-events', id, before, eventTarget],
    queryFn: () => api<Entry[]>(path + '/events?' + new URLSearchParams({
      ...(before ? { before: String(before) } : {}), ...(eventTarget ? { target_id: eventTarget } : {}),
    })),
    refetchInterval: before ? false : pollEvery(5000),
  })
  const [confirm, setConfirm] = useState(false)
  const client = useQueryClient()
  const cancel = useMutation({
    mutationFn: () => api<Job>(path + '/cancel', { method: 'POST', csrf: session.csrf_token }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['deployments'] })
      void client.invalidateQueries({ queryKey: ['deployment-events', id] })
    },
  })
  const job = query.data
  const [targetAction, setTargetAction] = useState<{ id: string; type: 'retry' | 'resolve'; key: string }>()
  const mutateTarget = useMutation({
    mutationFn: (action: NonNullable<typeof targetAction>) => api<Job>(`${path}/targets/${action.id}/${action.type}`, {
      method: 'POST', csrf: session.csrf_token,
      body: action.type === 'resolve' ? { verified_stopped: true } : { request_id: action.key },
    }),
    onSuccess: () => {
      setTargetAction(undefined)
      void client.invalidateQueries({ queryKey: ['deployments'] })
      void client.invalidateQueries({ queryKey: ['deployment-events', id] })
    },
  })
  const names = new Map(job?.targets.map(target => [target.id, target.hostname]))
  const stages: Record<string, string> = {
    checking: t('Проверка наличия', 'Checking presence'), downloading: t('Скачивается', 'Downloading'),
    executing: t('Запущен установщик', 'Installer running'), verifying: t('Проверяется', 'Verifying'),
    operator_resolved: t('Разрешено оператором', 'Resolved by operator'),
  }
  const eventsLabels: Record<string, string> = {
    ...stages,
    created: t('Задание создано', 'Job created'), leased: t('Попытка выдана', 'Attempt leased'),
    acknowledged: t('Получение подтверждено', 'Delivery acknowledged'), lease_expired: t('Срок выдачи истёк', 'Lease expired'),
    recovered: t('Связь восстановлена', 'Lease recovered'), delivery_failed: t('Исчерпаны попытки выдачи', 'Delivery attempts exhausted'),
    not_executed: t('Проверка завершилась без запуска', 'Transport test completed without execution'),
    cancel_requested: t('Запрошена отмена', 'Cancellation requested'), cancelled: t('Отменено', 'Cancelled'),
    awaiting_reboot: stateLabel('awaiting_reboot', t), reboot_required: stateLabel('reboot_required', t),
    reboot_verified: t('Результат подтверждён после перезагрузки', 'Result verified after restart'),
    reboot_timeout: diagnosis('reboot_timeout', t), detection_mismatch: diagnosis('detection_mismatch', t),
    detection_failed: diagnosis('detection_failed', t), device_removed: diagnosis('device_removed', t), device_retired: diagnosis('device_retired', t),
  }
  return <div className="grid gap-4">
    <Action secondary onClick={back}>{t('К очереди', 'Back to queue')}</Action>
    {query.isPending && <LoadingSkeleton label={t('Загрузка задания', 'Loading job')} />}
    <FormError message={(query.error || cancel.error) && errorMessage(query.error || cancel.error, t)} />
    {job && <Panel>
      <SectionTitle title={`${job.package_name} · ${job.version}`} description={operationLabel(job.operation, t)} actions={
        session.user.role !== 'viewer' && job.targets.some(target => target.state === 'queued' || target.state === 'leased' ||
          (target.state === 'running' && !target.cancel_requested))
          ? <Action secondary disabled={cancel.isPending} onClick={() => setConfirm(true)}>{t('Отменить задание', 'Cancel job')}</Action> : undefined
      } />
      <JobProgress job={job} t={t} />
      <FormError message={mutateTarget.error && errorMessage(mutateTarget.error, t)} />
      <ul className="mt-4 divide-y divide-border">{job.targets.map(target => <li key={target.id} className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm">
        <span className="break-all font-medium">{target.hostname}</span>
        <div className="flex flex-wrap items-center gap-2">
          {target.attempt && <span className="text-xs text-muted-foreground">{t('Попытка', 'Attempt')} {target.attempt}</span>}
          {target.recovery_required && <StatusBadge tone="warning">{t('Ожидается восстановление', 'Recovery required')}</StatusBadge>}
          {target.state === 'running' && target.cancel_requested && <StatusBadge tone="warning">{t('Запрошена отмена', 'Cancellation requested')}</StatusBadge>}
          <StatusBadge tone={target.state === 'failed' ? 'danger' : 'neutral'}>{stateLabel(target.state, t)}</StatusBadge>
          {target.stage && <span>{stages[target.stage] ?? target.stage}</span>}
          {target.exit_code != null && <code>{t('Код', 'Exit')}: {target.exit_code}</code>}
          {target.process_started === true && <span>{t('Процесс запущен', 'Process started')}</span>}
          {target.process_started === false && <span>{t('Процесс не запустился', 'Process failed to start')}</span>}
          {target.process_started == null && target.started_at && <span>{t('Запуск разрешён', 'Launch authorized')}</span>}
          {target.detection && <span>{detectionLabel(target.detection, t)}</span>}
          {target.reboot_detection && <span>{t('После перезагрузки', 'After restart')}: {detectionLabel(target.reboot_detection, t)}</span>}
          {target.state === 'awaiting_reboot' && target.reboot_deadline && <span>{t('Срок проверки', 'Verification deadline')}: {new Date(target.reboot_deadline).toLocaleString()}</span>}
          {[target.diagnostic, target.reboot_diagnostic].map((code, index) => code &&
            <span key={index} title={code}>{code === 'detection_failed' && !target.detection && !target.reboot_detection
              ? t('Результат обнаружения не подтверждён', 'Detection result could not be confirmed') : diagnosis(code, t)}</span>)}
          {target.output_bytes != null && <span>{t('Вывод, байт', 'Output bytes')}: {target.output_bytes}</span>}
          {target.recovery_required && session.user.role === 'super_admin' &&
            <Action secondary onClick={() => setTargetAction({ id: target.id, type: 'resolve', key: crypto.randomUUID() })}>{t('Разрешить вручную', 'Resolve manually')}</Action>}
          {target.state === 'failed' && session.user.role !== 'viewer' && (!target.retry_requires_admin || session.user.role === 'super_admin') &&
            <Action secondary onClick={() => setTargetAction({ id: target.id, type: 'retry', key: crypto.randomUUID() })}>{t('Повторить', 'Retry')}</Action>}
        </div>
      </li>)}</ul>
    </Panel>}
    <Panel>
      <SectionTitle title={t('Журнал развёртывания', 'Deployment log')} />
      {!!job?.targets.length && <label className="mb-4 grid max-w-80 gap-2 text-sm">{t('События устройства', 'Device events')}
        <select className="input" value={eventTarget} onChange={event => { setBefore(undefined); setEventTarget(event.target.value) }}>
          <option value="">{t('Все устройства', 'All devices')}</option>
          {job.targets.map(target => <option value={target.id} key={target.id}>{target.hostname}</option>)}
        </select>
      </label>}
      {events.isPending && <LoadingSkeleton label={t('Загрузка истории', 'Loading history')} />}
      <FormError message={events.error && errorMessage(events.error, t)} />
      {events.data?.length === 0 && <EmptyState title={t('Событий нет', 'No events')} />}
      {events.data && <ActivityFeed items={events.data.map(entry => ({
        key: entry.id, title: eventsLabels[entry.action] ?? entry.action,
        detail: [
          entry.target_id ? names.get(entry.target_id) : undefined,
          entry.attempt_number != null ? `${t('Попытка', 'Attempt')} ${entry.attempt_number}` : undefined,
        ].filter(Boolean).join(' · '), time: entry.created_at,
      }))} />}
      <div className="mt-3 flex flex-wrap gap-2">
        {before && <Action secondary onClick={() => setBefore(undefined)}>{t('К последним', 'Latest')}</Action>}
        {events.data?.length === 50 && <Action secondary onClick={() => setBefore(events.data?.at(-1)?.id)}>{t('Более ранние события', 'Earlier events')}</Action>}
      </div>
    </Panel>
    {targetAction && <ConfirmDialog
      title={targetAction.type === 'resolve' ? t('Разрешить неопределённый исход?', 'Resolve unknown outcome?') : t('Создать повторное задание?', 'Create a retry job?')}
      description={targetAction.type === 'resolve'
        ? t('Подтвердите, что установщик и его дочерние операции завершились на ПК. Это разблокирует выдачу.', 'Confirm the installer and related operations have stopped on the computer. This unblocks its queue.')
        : t('Будет создано отдельное задание для этого устройства.', 'A new job will be created for this device.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Назад', 'Back'), confirm: t('Подтвердить', 'Confirm') }}
      close={() => setTargetAction(undefined)} confirm={() => { if (!mutateTarget.isPending) mutateTarget.mutate(targetAction) }} />}
    {confirm && <ConfirmDialog title={t('Отменить задание?', 'Cancel job?')}
      description={t('Ожидающие выдачи отменятся. Подтверждённые попытки получат запрос отмены и завершатся после ответа агента.', 'Pending deliveries cancel immediately. Acknowledged attempts receive a cancellation request and wait for the agent.') }
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Назад', 'Back'), confirm: t('Отменить задание', 'Cancel job') }}
      close={() => setConfirm(false)} confirm={() => { setConfirm(false); cancel.mutate() }} />}
  </div>
}

export function DeploymentsPage({ session, t, preset, clearPreset, scope = 'all', selected, targetDevice, onScope, onSelect, clearDevice }: Props & {
  preset?: DeploymentPreset; clearPreset: () => void
  scope?: JobScope; selected?: string; targetDevice?: string
  onScope: (scope: JobScope) => void; onSelect: (id?: string) => void; clearDevice: () => void
}) {
  const [creating, setCreating] = useState(Boolean(preset))
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  const [operation, setOperation] = useState<Operation | ''>('')
  const [direction, setDirection] = useState<'asc' | 'desc'>('desc')
  const client = useQueryClient()
  const list = useQuery({
    queryKey: ['deployments', 'list', offset, scope, targetDevice, operation, term, direction], enabled: !selected, refetchInterval: pollEvery(5000),
    queryFn: () => api<{ items: Job[]; total: number }>(`/deployments?${new URLSearchParams({
      offset: String(offset), limit: String(pageSize), scope, direction, q: term,
      ...(targetDevice ? { device_id: targetDevice } : {}), ...(operation ? { operation } : {}),
    })}`),
  })
  if (selected) return <JobDetails key={selected} session={session} t={t} id={selected} back={() => onSelect()} />
  return <Panel>
    <SectionTitle title={t('Очередь развёртывания', 'Deployment queue')}
      description={t('Задания установки, обновления и удаления.', 'Install, upgrade and removal jobs.')}
      actions={session.user.role !== 'viewer' && <Action onClick={() => setCreating(true)}><Plus className="size-4" aria-hidden />{t('Новое задание', 'New job')}</Action>} />
    <form className="mb-4 flex flex-wrap items-end gap-3" onSubmit={event => {
      event.preventDefault(); setOffset(0); setTerm(search.trim())
    }}>
      <Field label={t('Программа или версия', 'Program or version')} maxLength={160} value={search} onChange={event => setSearch(event.target.value)} />
      <label className="grid gap-2 text-sm">{t('Состояние', 'Status')}
        <select className="input" value={scope} onChange={event => { setOffset(0); onScope(event.target.value as JobScope) }}>
          <option value="all">{t('Все', 'All')}</option><option value="active">{t('Активные', 'Active')}</option>
          <option value="problem">{t('Требуют внимания', 'Requires attention')}</option>
        </select>
      </label>
      <label className="grid gap-2 text-sm">{t('Операция', 'Operation')}
        <select className="input" value={operation} onChange={event => { setOffset(0); setOperation(event.target.value as Operation | '') }}>
          <option value="">{t('Все', 'All')}</option>
          <option value="install">{operationLabel('install', t)}</option><option value="uninstall">{operationLabel('uninstall', t)}</option>
        </select>
      </label>
      <label className="grid gap-2 text-sm">{t('Порядок', 'Order')}
        <select className="input" value={direction} onChange={event => { setOffset(0); setDirection(event.target.value === 'asc' ? 'asc' : 'desc') }}>
          <option value="desc">{t('Сначала новые', 'Newest first')}</option><option value="asc">{t('Сначала старые', 'Oldest first')}</option>
        </select>
      </label>
      <Action type="submit" secondary>{t('Поиск', 'Search')}</Action>
      {targetDevice && <Action type="button" secondary onClick={() => { setOffset(0); clearDevice() }}>
        {t('Сбросить фильтр устройства', 'Clear device filter')}
      </Action>}
    </form>
    {list.isPending && <LoadingSkeleton label={t('Загрузка очереди', 'Loading queue')} />}
    <FormError message={list.error && errorMessage(list.error, t)} />
    {list.data?.items.length === 0 && <EmptyState icon={ListTodo} title={term || scope !== 'all' || operation || targetDevice ? t('Задания по фильтру не найдены', 'No matching jobs') : t('Заданий пока нет', 'No jobs yet')} />}
    <ul className="divide-y divide-border">{list.data?.items.map(job => <li key={job.id} className="grid items-start gap-2 py-3 sm:grid-cols-2">
      <div>
        <button type="button" className="break-words text-left text-sm font-semibold text-primary hover:underline"
          onClick={() => onSelect(job.id)}>{job.package_name} · {job.version}</button>
        <p className="mt-1 text-xs text-muted-foreground">{operationLabel(job.operation, t)} · {new Date(job.created_at).toLocaleString()}</p>
      </div>
      <JobProgress job={job} t={t} />
    </li>)}</ul>
    {(offset > 0 || (list.data?.total ?? 0) > pageSize) && <div className="mt-3 flex flex-wrap gap-2">
      <Action secondary disabled={offset === 0} onClick={() => setOffset(offset - pageSize)}>{t('Предыдущая', 'Previous')}</Action>
      <Action secondary disabled={offset + pageSize >= (list.data?.total ?? 0)} onClick={() => setOffset(offset + pageSize)}>{t('Следующая', 'Next')}</Action>
    </div>}
    {creating && <NewJob session={session} t={t} preset={preset} close={() => { setCreating(false); clearPreset() }} created={id => {
      setCreating(false); clearPreset(); onSelect(id); void client.invalidateQueries({ queryKey: ['deployments'] })
    }} />}
  </Panel>
}
