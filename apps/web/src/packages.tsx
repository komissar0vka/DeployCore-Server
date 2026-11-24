import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { MoreHorizontal, Package, Plus, UploadCloud } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import type { DeploymentPreset } from './deployments'
import { api, pollEvery, upload, type Session } from './api'
import { Dialog } from './components/ui/dialog'
import { Dropdown } from './components/ui/dropdown'
import { ConfirmDialog, EmptyState, LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, Field, FormError, Panel, detectionLabel, errorMessage, type Translate } from './ui'

interface ProductFields { name: string; publisher: string; description: string; category: string }
interface Product extends ProductFields { id: string; can_deploy?: boolean }
interface Artifact { filename: string; size_bytes: number; sha256: string; signature: 'verified' | 'unverified' }
type DetectionLeaf = { kind: 'msi_product'; product_code: string } | { kind: 'registry_software'; display_name: string; version: string }
  | { kind: 'file_exists'; path: string } | { kind: 'file_version'; path: string; version: string }
type Detection = DetectionLeaf | { kind: 'all'; schema_version: 1; rules: DetectionLeaf[] }
  | { kind: 'any'; schema_version: 1; rules: DetectionLeaf[] }
interface VersionInput {
  version: string
  architecture: 'x64' | 'x86'
  installer: 'msi' | 'exe'
  min_windows_build: number | null
  install_args: string[]
  uninstall_args: string[] | null
  detection: Detection
  timeout_seconds: number
  success_codes: number[]
  reboot_required: boolean
}
interface Version extends VersionInput { editable: boolean; revision: number; id: string; approved_at: string | null; approval_kind: 'authenticode' | 'manual' | null; artifact: Artifact | null }
interface Props { session: Session; t: Translate }
const pageSize = 25

function ProductDialog({ product, close, save, pending, error, t }: {
  product?: Product; close: () => void; save: (body: ProductFields) => void; pending: boolean; error: unknown; t: Translate
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    save({ name: String(data.get('name')), publisher: String(data.get('publisher')), description: String(data.get('description')), category: String(data.get('category')) })
  }
  return <Dialog title={product ? t('Редактировать программу', 'Edit program') : t('Новая программа', 'New program')}
    close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={submit}>
      <Field name="name" label={t('Название', 'Name')} maxLength={160} required defaultValue={product?.name} />
      <Field name="publisher" label={t('Издатель', 'Publisher')} maxLength={160} required defaultValue={product?.publisher} />
      <Field name="category" label={t('Категория', 'Category')} maxLength={160} defaultValue={product?.category} />
      <label className="grid gap-2 text-sm">{t('Описание', 'Description')}
        <textarea className="input min-h-20" name="description" maxLength={4000} defaultValue={product?.description} />
      </label>
      <FormError message={error ? errorMessage(error, t) : null} />
      <Action type="submit" disabled={pending}>{t('Сохранить', 'Save')}</Action>
    </form>
  </Dialog>
}

function readLeaf(read: (name: string) => string, index: number): DetectionLeaf {
  const kind = read(`ruleKind${index}`)
  const version = read(`detectedVersion${index}`)
  const path = read(`filePath${index}`)
  switch (kind) {
    case 'msi_product': return { kind, product_code: read(`productCode${index}`) }
    case 'registry_software': return { kind, display_name: read(`display${index}`), version }
    case 'file_version': return { kind, path, version }
    default: return { kind: 'file_exists', path }
  }
}

function DetectionFields({ index, t, initial }: { index: number; t: Translate; initial?: DetectionLeaf }) {
  const [kind, setKind] = useState<DetectionLeaf['kind']>(initial?.kind ?? 'registry_software')
  return <fieldset className="grid gap-3 rounded border border-border p-3">
    <label className="grid gap-2 text-sm">{t('Тип правила', 'Rule type')}
      <select className="input" name={`ruleKind${index}`} value={kind} onChange={event => setKind(event.target.value as DetectionLeaf['kind'])}>
        <option value="registry_software">{t('Имя и версия в реестре', 'Registry name and version')}</option>
        <option value="msi_product">MSI ProductCode</option>
        <option value="file_exists">{t('Наличие файла', 'File exists')}</option>
        <option value="file_version">{t('Версия файла', 'File version')}</option>
      </select>
    </label>
    {kind === 'msi_product' && <Field name={`productCode${index}`} label="MSI ProductCode" required maxLength={38} defaultValue={initial?.kind === kind ? initial.product_code : undefined} />}
    {kind === 'registry_software' && <Field name={`display${index}`} label={t('Имя в реестре', 'Registry display name')} required maxLength={160} defaultValue={initial?.kind === kind ? initial.display_name : undefined} />}
    {(kind === 'file_exists' || kind === 'file_version') && <Field name={`filePath${index}`} label={t('Абсолютный путь к файлу', 'Absolute file path')} required maxLength={240} defaultValue={initial && 'path' in initial ? initial.path : undefined} />}
    {(kind === 'registry_software' || kind === 'file_version') && <Field key={kind} name={`detectedVersion${index}`}
      label={kind === 'file_version' ? t('Версия файла', 'File version') : t('Версия в реестре', 'Registry version')} required maxLength={120} defaultValue={initial && 'version' in initial ? initial.version : undefined} />}
  </fieldset>
}

function describeRule(rule: Detection, t: Translate): string {
  switch (rule.kind) {
    case 'all':
    case 'any':
      return `${rule.kind === 'all' ? t('Все правила', 'All rules') : t('Любое правило', 'Any rule')} (${rule.rules.map(child => describeRule(child, t)).join(' · ')})`
    case 'msi_product': return rule.product_code
    case 'registry_software': return `${rule.display_name} (${rule.version})`
    case 'file_version': return `${rule.path} (${rule.version})`
    case 'file_exists': return rule.path
  }
}

function VersionDialog({ t, close, save, pending, error, initial }: {
  t: Translate; close: () => void; save: (body: VersionInput) => void; pending: boolean; error: unknown; initial?: Version
}) {
  const rule = initial?.detection
  const initialGroup = rule && 'rules' in rule ? rule : undefined
  const [group, setGroup] = useState<'single' | 'all' | 'any'>(initialGroup?.kind ?? 'single')
  const [ruleCount, setRuleCount] = useState(initialGroup?.rules.length ?? 2)
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    const read = (name: string) => String(fields.get(name) ?? '').trim()
    const lines = (name: string) => read(name).split(/\r?\n/).map(line => line.trim()).filter(Boolean)
    save({
      version: read('version'), architecture: read('architecture') as VersionInput['architecture'],
      installer: read('installer') as VersionInput['installer'],
      min_windows_build: read('build') ? Number(read('build')) : null,
      install_args: lines('install'), uninstall_args: fields.get('remove') ? lines('uninstall') : null,
      timeout_seconds: Number(read('timeout')), success_codes: read('codes').split(',').map(value => Number(value.trim())),
      reboot_required: fields.has('reboot'),
      detection: group === 'single' ? readLeaf(read, 0) : {
        kind: group, schema_version: 1, rules: Array.from({ length: ruleCount }, (_, index) => readLeaf(read, index)),
      },
    })
  }
  return <Dialog title={initial ? initial.editable ? t('Редактировать версию', 'Edit version') : t('Новая ревизия', 'New revision') : t('Новая версия', 'New version')} close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={submit}>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field name="version" label={t('Версия', 'Version')} required maxLength={80} defaultValue={initial?.version} />
        <label className="grid gap-2 text-sm">{t('Тип', 'Type')}<select className="input" name="installer" defaultValue={initial?.installer} aria-label={t('Тип', 'Type')}><option value="msi">MSI</option><option value="exe">EXE</option></select></label>
        <label className="grid gap-2 text-sm">{t('Архитектура', 'Architecture')}<select className="input" name="architecture" defaultValue={initial?.architecture} aria-label={t('Архитектура', 'Architecture')}><option>x64</option><option>x86</option></select></label>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field name="build" label={t('Мин. сборка Windows', 'Min. Windows build')} type="number" min={1} max={2147483647} defaultValue={initial?.min_windows_build ?? undefined} />
        <Field name="timeout" label={t('Таймаут, с', 'Timeout, s')} type="number" min={1} max={86400} required defaultValue={initial?.timeout_seconds ?? 1800} />
      </div>
      <Field name="codes" label={t('Допустимые коды через запятую', 'Accepted exit codes, comma-separated')}
        pattern="[0-9]+(, *[0-9]+)*" required defaultValue={initial?.success_codes.join(', ') ?? '0, 3010'} />
      <label className="grid gap-2 text-sm">{t('Аргументы установки, по одному в строке', 'Installation arguments, one per line')}
        <textarea className="input" name="install" maxLength={12000} defaultValue={initial?.install_args?.join('\n')} />
      </label>
      <label className="grid gap-2 text-sm">{t('Аргументы удаления, по одному в строке', 'Removal arguments, one per line')}
        <textarea className="input" name="uninstall" maxLength={12000} defaultValue={initial?.uninstall_args?.join('\n')} />
      </label>
      <label className="text-sm"><input name="remove" type="checkbox" defaultChecked={initial?.uninstall_args != null} /> {t('Разрешить удаление', 'Allow removal')}</label>
      <label className="text-sm"><input name="reboot" type="checkbox" defaultChecked={initial?.reboot_required} /> {t('Требуется перезагрузка', 'Restart required')}</label>
      <label className="grid gap-2 text-sm">{t('Правило обнаружения', 'Detection rule')}
        <select className="input" value={group} onChange={event => setGroup(event.target.value as typeof group)}>
          <option value="single">{t('Одно правило', 'Single rule')}</option>
          <option value="all">{t('Все правила', 'All rules')}</option>
          <option value="any">{t('Любое правило', 'Any rule')}</option>
        </select>
      </label>
      {Array.from({ length: group === 'single' ? 1 : ruleCount }, (_, index) => <DetectionFields key={index} index={index} t={t} initial={initialGroup?.rules[index] ?? (index === 0 && rule && !('rules' in rule) ? rule : undefined)} />)}
      {group !== 'single' && <div className="flex flex-wrap gap-2">
        <Action type="button" secondary disabled={ruleCount >= 8} onClick={() => setRuleCount(ruleCount + 1)}>{t('Добавить правило', 'Add rule')}</Action>
        <Action type="button" secondary disabled={ruleCount <= 2} onClick={() => setRuleCount(ruleCount - 1)}>{t('Удалить последнее правило', 'Remove last rule')}</Action>
      </div>}
      <FormError message={error ? errorMessage(error, t) : null} />
      <Action type="submit" disabled={pending}>{initial ? t('Сохранить', 'Save') : t('Добавить версию', 'Add version')}</Action>
    </form>
  </Dialog>
}

function UploadForm({ path, installer, csrf, t, uploaded, replace = false }: {
  path: string; installer: string; csrf: string; t: Translate; uploaded: () => void; replace?: boolean
}) {
  const [controller, setController] = useState<AbortController | null>(null)
  const [problem, setProblem] = useState('')
  useEffect(() => () => controller?.abort(), [controller])
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const selected = new FormData(event.currentTarget).get('file')
    if (!(selected instanceof File) || !selected.size) return
    const active = new AbortController()
    setController(active)
    setProblem('')
    try {
      await api<Artifact>(`${path}?${new URLSearchParams({ filename: selected.name, ...(replace ? { replace: 'true' } : {}) })}`, {
        method: 'PUT', body: selected, csrf, signal: active.signal,
      })
      uploaded()
    } catch (error) {
      if (!active.signal.aborted) setProblem(errorMessage(error, t))
    } finally {
      setController(null)
    }
  }
  return <form className="grid gap-2" onSubmit={submit}>
    <Field type="file" name="file" accept={'.' + installer} label={t('Установщик', 'Installer')} required disabled={!!controller} />
    <div className="flex flex-wrap gap-2">
      <Action type="submit" disabled={!!controller}>{replace ? t('Заменить и проверить', 'Replace and verify') : t('Загрузить и проверить', 'Upload and verify')}</Action>
      {controller && <Action secondary onClick={() => controller.abort()}>{t('Отменить загрузку', 'Cancel upload')}</Action>}
    </div>
    {controller && <p role="status" className="text-sm text-muted-foreground">{t('Загрузка и проверка подписи…', 'Uploading and verifying signature…')}</p>}
    <FormError message={problem} />
  </form>
}

function ManualApprovalDialog({ artifact, close, save, pending, error, t }: {
  artifact: Artifact; close: () => void; save: (sha256: string) => void; pending: boolean; error: unknown; t: Translate
}) {
  const [sha256, setSha256] = useState('')
  const matches = sha256.trim().toLowerCase() === artifact.sha256
  return <Dialog title={t('Утвердить версию вручную', 'Approve version manually')}
    close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={event => {
      event.preventDefault()
      if (matches && !pending) save(sha256.trim())
    }}>
      <p className="text-sm">{t(
        'Подпись не подтверждена. Проверьте источник файла и введите SHA-256, вычисленный по доверенной копии установщика.',
        'The signature is unverified. Check the file source and enter the SHA-256 computed from a trusted copy of the installer.',
      )}</p>
      <span className="break-all text-sm">{artifact.filename}</span>
      <code className="break-all text-xs">SHA-256 {artifact.sha256}</code>
      <Field label={t('Подтвердите SHA-256', 'Confirm SHA-256')} name="sha256" value={sha256}
        onChange={event => setSha256(event.target.value)} autoComplete="off" spellCheck={false} required />
      <FormError message={error ? errorMessage(error, t) : null} />
      <Action type="submit" disabled={!matches || pending}>{t('Утвердить вручную', 'Approve manually')}</Action>
    </form>
  </Dialog>
}

interface Preview { id: string; status: 'queued' | 'checking' | 'completed' | 'expired'; observation: string | null }

function DetectionPreviewDialog({ version, csrf, close, t }: { version: string; csrf: string; close: () => void; t: Translate }) {
  const [search, setSearch] = useState('')
  const [device, setDevice] = useState('')
  const devices = useQuery({
    queryKey: ['preview-devices', search],
    queryFn: () => api<{ items: { id: string; hostname: string; agent_revoked: boolean; agent_version: string }[] }>(
      `/devices?${new URLSearchParams({ q: search, limit: '25' })}`),
  })
  const start = useMutation({
    mutationFn: () => api<Preview>('/detection-previews', { method: 'POST', csrf, body: { version_id: version, device_id: device } }),
  })
  const result = useQuery({
    queryKey: ['detection-preview', start.data?.id], enabled: !!start.data,
    queryFn: () => api<Preview>(`/detection-previews/${start.data?.id}`),
    refetchInterval: query => query.state.data?.status === 'completed' || query.state.data?.status === 'expired' ? false : pollEvery(2000)(query),
  })
  const status = (result.data ?? start.data)?.status
  const observation = result.data?.observation
  const error = devices.error || start.error || result.error
  return <Dialog title={t('Проверить обнаружение', 'Preview detection')} close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={event => { event.preventDefault(); if (device && !start.data && !start.isPending) start.mutate() }}>
      <p className="text-sm">{t('Выберите тестовое устройство с Agent 0.3.5 или новее. Агент проверит только правило обнаружения.',
        'Select a test device running Agent 0.3.5 or later. The agent checks the detection rule only.')}</p>
      <Field name="deviceSearch" label={t('Поиск устройства', 'Find device')} value={search} maxLength={120} disabled={!!status || start.isPending}
        onChange={event => { setSearch(event.target.value); setDevice('') }} />
      <label className="grid gap-2 text-sm">{t('Тестовое устройство', 'Test device')}
        <select className="input" required value={device} disabled={!!status || start.isPending} onChange={event => setDevice(event.target.value)}>
          <option value="">{t('Выберите устройство', 'Select device')}</option>
          {devices.data?.items.filter(item => !item.agent_revoked).map(item =>
            <option key={item.id} value={item.id}>{item.hostname} · {item.agent_version}</option>)}
        </select>
      </label>
      <FormError message={error ? errorMessage(error, t) : null} />
      {status && <p role="status" className="text-sm">
        {observation ? detectionLabel(observation, t) : {
          queued: t('Ожидает агента', 'Waiting for agent'), checking: t('Агент проверяет правило', 'Agent is checking'),
          expired: t('Время проверки истекло', 'Preview expired'), completed: '',
        }[status]}
      </p>}
      <Action type="submit" disabled={!device || start.isPending || !!status}>{t('Запустить проверку', 'Run preview')}</Action>
    </form>
  </Dialog>
}

function packageAction(action: string, t: Translate) {
  const labels: Record<string, string> = {
    package_created: t('Добавлена программа', 'Program added'), package_changed: t('Изменены сведения', 'Program updated'),
    package_version_created: t('Добавлена версия', 'Version added'), package_version_changed: t('Изменена версия', 'Version updated'),
    package_version_revised: t('Создана ревизия', 'Revision created'), package_version_deleted: t('Удалена версия', 'Version deleted'),
    package_artifact_uploaded: t('Загружен установщик', 'Installer uploaded'), package_artifact_replaced: t('Заменён установщик', 'Installer replaced'),
    package_version_approved: t('Утверждена версия', 'Version approved'), package_duplicated: t('Создана копия', 'Program duplicated'),
  }
  return labels[action] ?? t('Обновлена программа', 'Program updated')
}

function ProductDetails({ id, back, session, t, deploy, selectedPackage }: Props & { id: string; back: () => void; selectedPackage: (id: string) => void; deploy: (preset: DeploymentPreset) => void }) {
  const client = useQueryClient()
  const path = '/packages/' + id
  const query = useQuery({ queryKey: ['package', id], queryFn: () => api<Product & { versions: Version[] }>(path) })
  const [modal, setModal] = useState<'edit' | 'version' | 'archive' | 'duplicate' | 'purge' | 'history' | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [editingVersion, setEditingVersion] = useState<Version>()
  const [replacingVersion, setReplacingVersion] = useState<Version>()
  const [deletingVersion, setDeletingVersion] = useState<Version>()
  const [notice, setNotice] = useState('')
  const [manual, setManual] = useState<{ version: string; artifact: Artifact } | null>(null)
  const writable = session.user.role !== 'viewer'
  const csrf = session.csrf_token
  function updated() {
    void client.invalidateQueries({ queryKey: ['package', id] })
    void client.invalidateQueries({ queryKey: ['packages'] })
    void client.invalidateQueries({ queryKey: ['package-history', id] })
  }
  const edit = useMutation({ mutationFn: (body: ProductFields) => api<Product>(path, { method: 'PATCH', body, csrf }),
    onSuccess: () => { updated(); setModal(null) } })
  const add = useMutation({ mutationFn: (body: VersionInput) => api<Version>(path + '/versions', { method: 'POST', body, csrf }),
    onSuccess: () => { updated(); setModal(null) } })
  const editVersion = useMutation({
    mutationFn: ({ version, body }: { version: Version; body: VersionInput }) =>
      version.editable
        ? api<Version>(`${path}/versions/${version.id}`, { method: 'PUT', body, csrf })
        : api<Version>(`${path}/versions/${version.id}/revisions`, { method: 'POST', body, csrf }),
    onSuccess: () => { updated(); setEditingVersion(undefined); setNotice(t('Версия сохранена.', 'Version saved.')) },
  })
  const duplicate = useMutation({
    mutationFn: (body: ProductFields) => api<Product>(path + '/duplicate', { method: 'POST', body, csrf }),
    onSuccess: record => { updated(); setModal(null); selectedPackage(record.id) },
  })
  const remove = useMutation({
    mutationFn: (versionId?: string) => api<void>(versionId ? `${path}/versions/${versionId}` : path + '/purge', { method: 'DELETE', csrf }),
    onSuccess: (_data, versionId) => {
      updated(); setDeletingVersion(undefined); setModal(null)
      if (versionId) setNotice(t('Версия удалена.', 'Version deleted.'))
      else back()
    },
  })
  const history = useQuery({
    queryKey: ['package-history', id], enabled: modal === 'history',
    queryFn: () => api<{ action: string; actor: string | null; created_at: string }[]>(path + '/history'),
  })
  const archive = useMutation({ mutationFn: () => api<void>(path, { method: 'DELETE', csrf }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['packages'] }); back() } })
  const approval = useMutation({ mutationFn: (version: string) => api<Version>(`${path}/versions/${version}/approve`, { method: 'POST', csrf }),
    onSuccess: updated })
  const manualApproval = useMutation({
    mutationFn: ({ version, sha256 }: { version: string; sha256: string }) =>
      api<Version>(`${path}/versions/${version}/approve-manual`, { method: 'POST', body: { sha256 }, csrf }),
    onSuccess: () => { updated(); setManual(null) },
  })
  const product = query.data

  return <div className="grid gap-4">
    {notice && <p role="status" className="text-sm text-success">{notice}</p>}
    <Action secondary onClick={back}>{t('К каталогу', 'Back to catalog')}</Action>
    {query.isPending && <LoadingSkeleton label={t('Загрузка программы', 'Loading program')} />}
    <FormError message={(query.error || archive.error || approval.error) && errorMessage(query.error || archive.error || approval.error, t)} />
    {product && <Panel>
      <SectionTitle title={product.name} description={[product.publisher, product.category].filter(Boolean).join(' · ')} actions={<div className="flex flex-wrap gap-2">
        {writable && <>
          <Action secondary onClick={() => { edit.reset(); setModal('edit') }}>{t('Редактировать', 'Edit')}</Action>
          <Action onClick={() => { add.reset(); setModal('version') }}>{t('Новая версия', 'New version')}</Action>
        </>}
        <Dropdown label={t('Действия с программой', 'Program actions')} trigger={<MoreHorizontal className="size-5" aria-hidden />}>
          {close => <div className="grid gap-1">
            <Action secondary onClick={() => { close(); setModal('history') }}>{t('История изменений', 'Change history')}</Action>
            {writable && <>
              <Action secondary onClick={() => { close(); duplicate.reset(); setModal('duplicate') }}>{t('Дублировать', 'Duplicate')}</Action>
              <Action secondary onClick={() => { close(); setModal('archive') }} disabled={archive.isPending}>{t('Архивировать', 'Archive')}</Action>
              {product.versions.every(version => version.editable) &&
                <Action secondary onClick={() => { close(); remove.reset(); setModal('purge') }}>{t('Удалить программу', 'Delete program')}</Action>}
            </>}
          </div>}
        </Dropdown>
      </div>} />
      {product.description && <p className="mb-3 break-words text-sm text-muted-foreground">{product.description}</p>}
      {!product.versions.length && <EmptyState title={t('Версий пока нет', 'No versions yet')} />}
      <div className="grid gap-3">
        {product.versions.map(version => {
          const artifactPath = `${path}/versions/${version.id}/artifact`
          return <details key={version.id} className="rounded-xl border border-border px-3 py-2.5">
            <summary className="cursor-pointer text-sm"><strong>{version.version}</strong> {version.revision > 1 && t(`(ревизия ${version.revision})`, `(revision ${version.revision})`)} · {version.installer.toUpperCase()} {version.architecture}
              <span className="ml-2"><StatusBadge tone={version.approved_at ? 'success' : 'neutral'}>
                {version.approval_kind === 'manual' ? t('Утверждена вручную', 'Manually approved')
                  : version.approved_at ? t('Утверждена', 'Approved') : t('Черновик', 'Draft')}
              </StatusBadge></span>
            </summary>
            <div className="mt-3 grid min-w-0 gap-3">
              <dl className="grid gap-1 text-sm text-muted-foreground sm:grid-cols-[auto_1fr] sm:gap-x-4">
                <dt>{t('Минимальная сборка Windows', 'Minimum Windows build')}</dt><dd>{version.min_windows_build ?? '—'}</dd>
                <dt>{t('Таймаут и коды завершения', 'Timeout and exit codes')}</dt><dd>{version.timeout_seconds} s · {version.success_codes.join(', ')}</dd>
                <dt>{t('Перезагрузка', 'Restart')}</dt><dd>{version.reboot_required ? t('Требуется', 'Required') : t('По результату', 'Based on result')}</dd>
                <dt>{t('Обнаружение', 'Detection')}</dt><dd className="break-all">{describeRule(version.detection, t)}</dd>
                <dt>{t('Аргументы установки', 'Installation arguments')}</dt><dd className="break-all font-mono">{JSON.stringify(version.install_args)}</dd>
                <dt>{t('Аргументы удаления', 'Removal arguments')}</dt><dd className="break-all font-mono">{version.uninstall_args === null ? '—' : JSON.stringify(version.uninstall_args)}</dd>
              </dl>
              {writable && <div className="flex flex-wrap gap-2">
                <Action secondary onClick={() => { editVersion.reset(); setEditingVersion(version) }}>
                  {version.editable ? t('Редактировать версию', 'Edit version') : t('Создать ревизию', 'Create revision')}
                </Action>
                {version.editable && <Action secondary onClick={() => { remove.reset(); setDeletingVersion(version) }}>{t('Удалить версию', 'Delete version')}</Action>}
                {version.editable && version.artifact && <Action secondary onClick={() => setReplacingVersion(version)}>{t('Заменить файл', 'Replace file')}</Action>}
                <Action secondary onClick={() => setPreview(version.id)}>{t('Проверить обнаружение', 'Preview detection')}</Action>
              </div>}
              {version.artifact ? <div className="grid gap-2 text-sm">
                <span className="break-all">{version.artifact.filename} · {(version.artifact.size_bytes / 1048576).toFixed(2)} MiB</span>
                <code className="break-all text-xs">SHA-256 {version.artifact.sha256}</code>
                <div><StatusBadge tone={version.artifact.signature === 'verified' ? 'success' : 'warning'}>
                  {version.artifact.signature === 'verified' ? t('Authenticode проверен', 'Authenticode verified') : t('Подпись не подтверждена', 'Signature unverified')}
                </StatusBadge></div>
                {writable && <div className="flex flex-wrap items-center gap-3">
                  <a className="text-primary hover:underline" href={'/api/v1' + artifactPath} download>{t('Скачать установщик', 'Download installer')}</a>
                  {version.approved_at && <Action onClick={() => deploy({ packageId: id, versionId: version.id, productName: product.name })}>
                    {t('Установить', 'Install')}
                  </Action>}
                  {!version.approved_at && version.artifact.signature === 'verified' &&
                    <Action disabled={approval.isPending} onClick={() => approval.mutate(version.id)}>{t('Утвердить версию', 'Approve version')}</Action>}
                  {!version.approved_at && version.artifact.signature === 'unverified' && session.user.role === 'super_admin' &&
                    <Action onClick={() => {
                      if (version.artifact) {
                        manualApproval.reset()
                        setManual({ version: version.id, artifact: version.artifact })
                      }
                    }}>{t('Утвердить вручную', 'Approve manually')}</Action>}
                </div>}
              </div> : writable ? <UploadForm path={artifactPath} installer={version.installer} csrf={csrf} t={t} uploaded={updated} />
                : <EmptyState title={t('Установщик ещё не загружен', 'No installer uploaded yet')} />}
            </div>
          </details>
        })}
      </div>
    </Panel>}
    {editingVersion && <VersionDialog initial={editingVersion} t={t} close={() => setEditingVersion(undefined)}
      save={body => editVersion.mutate({ version: editingVersion, body })} pending={editVersion.isPending} error={editVersion.error} />}
    {replacingVersion && <Dialog title={t('Заменить установщик', 'Replace installer')} close={() => setReplacingVersion(undefined)} closeLabel={t('Закрыть', 'Close')}>
      <p className="mb-3 text-sm">{t('Новый файл будет проверен. Версию потребуется утвердить заново.', 'The new file will be verified and the version will require approval again.')}</p>
      <UploadForm path={`${path}/versions/${replacingVersion.id}/artifact`} installer={replacingVersion.installer} csrf={csrf} t={t}
        replace uploaded={() => { updated(); setReplacingVersion(undefined); setNotice(t('Установщик заменён.', 'Installer replaced.')) }} />
    </Dialog>}
    {preview && <DetectionPreviewDialog version={preview} csrf={csrf} t={t} close={() => setPreview(null)} />}
    {manual && <ManualApprovalDialog artifact={manual.artifact} t={t} close={() => setManual(null)}
      save={sha256 => manualApproval.mutate({ version: manual.version, sha256 })}
      pending={manualApproval.isPending} error={manualApproval.error} />}
    {modal === 'edit' && product && <ProductDialog product={product} t={t} close={() => setModal(null)}
      save={body => edit.mutate(body)} pending={edit.isPending} error={edit.error} />}
    {modal === 'version' && <VersionDialog t={t} close={() => setModal(null)}
      save={body => add.mutate(body)} pending={add.isPending} error={add.error} />}
    {modal === 'duplicate' && product && <ProductDialog product={{ ...product, name: (product.name.slice(0, 148) + t(' — копия', ' — copy')) }}
      t={t} close={() => setModal(null)} save={body => duplicate.mutate(body)} pending={duplicate.isPending} error={duplicate.error} />}
    {(deletingVersion || modal === 'purge') && <Dialog title={deletingVersion ? t('Удалить версию?', 'Delete version?') : t('Удалить программу?', 'Delete program?')}
      close={() => { setModal(null); setDeletingVersion(undefined) }} closeLabel={t('Закрыть', 'Close')}>
      <div className="grid gap-3">
        <p className="text-sm">{t('Удаление необратимо. Версии из истории развёртываний защищены.', 'Deletion is permanent. Versions in deployment history are protected.')}</p>
        <FormError message={remove.error ? errorMessage(remove.error, t) : null} />
        <Action disabled={remove.isPending} onClick={() => remove.mutate(deletingVersion?.id)}>{t('Удалить', 'Delete')}</Action>
      </div>
    </Dialog>}
    {modal === 'history' && <Dialog title={t('История изменений', 'Change history')} close={() => setModal(null)} closeLabel={t('Закрыть', 'Close')}>
      <FormError message={history.error ? errorMessage(history.error, t) : null} />
      {history.isPending ? <LoadingSkeleton label={t('Загрузка истории', 'Loading history')} />
        : !history.data?.length ? <EmptyState title={t('Изменений пока нет', 'No changes yet')} />
        : <ul className="divide-y divide-border text-sm">{history.data.map((event, index) => <li key={index} className="py-2">
          <p>{packageAction(event.action, t)}</p>
          <p className="text-muted-foreground">{event.actor ?? '—'} · {new Date(event.created_at).toLocaleString(t('ru', 'en'))}</p>
        </li>)}</ul>}
    </Dialog>}
    {modal === 'archive' && <ConfirmDialog title={t('Архивировать программу?', 'Archive program?')}
      description={t('Программа исчезнет из каталога. Версии и установщики сохранятся.', 'The program is hidden. Versions and files are retained.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Архивировать', 'Archive') }}
      close={() => setModal(null)} confirm={() => { setModal(null); archive.mutate() }} />}
  </div>
}

interface Intake extends Artifact {
  id: string
  installer: VersionInput['installer']
  architecture: VersionInput['architecture']
  name: string | null
  publisher: string | null
  version: string | null
  product_code: string | null
  family: 'inno' | 'nsis' | 'installshield' | 'installshield_basic_msi' | null
  install_args: string[]
  uninstall_args: string[] | null
}

function IntakeDialog({ session, t, close, saved }: Props & { close: () => void; saved: (product: Product) => void }) {
  const [preview, setPreview] = useState<Intake>()
  const [operation, setOperation] = useState<AbortController>()
  const [progress, setProgress] = useState(0)
  const [problem, setProblem] = useState('')
  const [overrideDetection, setOverrideDetection] = useState(false)
  useEffect(() => () => operation?.abort(), [operation])
  const create = useMutation({
    mutationFn: (body: { package: ProductFields; version: VersionInput }) =>
      api<{ package: Product }>(`/packages/intakes/${preview?.id}/save`, { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: result => saved(result.package),
  })

  async function inspect(file: File | undefined) {
    if (!file || operation || create.isPending) return
    if (!/\.(exe|msi)$/i.test(file.name) || !file.size) {
      setProblem(t('Выбери непустой файл EXE или MSI.', 'Select a non-empty EXE or MSI file.'))
      return
    }
    const controller = new AbortController()
    create.reset()
    setPreview(undefined)
    setOverrideDetection(false)
    setProblem('')
    setProgress(0)
    setOperation(controller)
    try {
      setPreview(await upload<Intake>(`/packages/intakes?${new URLSearchParams({ filename: file.name })}`,
        file, session.csrf_token, setProgress, controller.signal))
    } catch (error) {
      if (!controller.signal.aborted) setProblem(errorMessage(error, t))
    } finally {
      setOperation(undefined)
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!preview || create.isPending) return
    const fields = new FormData(event.currentTarget)
    const read = (name: string) => String(fields.get(name) ?? '').trim()
    const args = (name: string) => read(name).split(/\r?\n/).filter(Boolean)
    const name = read('name')
    const version = read('version')
    const detection: Detection = overrideDetection ? readLeaf(read, 0)
      : preview.product_code ? { kind: 'msi_product', product_code: preview.product_code }
      : { kind: 'registry_software', display_name: name, version }
    create.mutate({
      package: { name, publisher: read('publisher'), description: read('description'), category: read('category') },
      version: {
        version, architecture: preview.architecture, installer: preview.installer, detection,
        install_args: args('install'), uninstall_args: fields.has('remove') ? args('uninstall') : null,
        min_windows_build: null, timeout_seconds: 1800, success_codes: [0, 3010], reboot_required: false,
      },
    })
  }

  return <Dialog title={t('Добавить программу', 'Add program')} close={close} closeLabel={t('Закрыть', 'Close')}>
    <div className="grid gap-3">
      {!preview && <div className="grid place-items-center gap-3 rounded-xl border border-dashed border-border p-6 text-center"
        onDragOver={event => { event.preventDefault(); event.dataTransfer.dropEffect = 'copy' }}
        onDrop={event => { event.preventDefault(); void inspect(event.dataTransfer.files[0]) }}>
        <UploadCloud aria-hidden className="size-6 text-muted-foreground" />
        <Field type="file" accept=".exe,.msi" disabled={!!operation} label={t('Перетащи EXE или MSI сюда либо выбери файл', 'Drop an EXE or MSI here, or choose a file')}
          onChange={event => void inspect(event.target.files?.[0])} />
      </div>}
      {operation && <div className="grid gap-2" role="status">
        <span>{progress === 100 ? t('Проверяем файл…', 'Checking the file…') : t('Загрузка файла', 'Uploading file') + ` ${progress}%`}</span>
        <progress className="w-full" max={100} value={progress} />
        <div><Action secondary onClick={() => operation.abort()}>{t('Отменить загрузку', 'Cancel upload')}</Action></div>
      </div>}
      <FormError message={problem} />
      {preview && <form className="grid gap-3" onSubmit={submit}>
        <div className="rounded-lg border border-border p-3">
          <p className="break-words font-medium">{preview.filename}</p>
          <p className="text-sm text-muted-foreground">{preview.installer.toUpperCase()} · {preview.architecture} · {(preview.size_bytes / 1048576).toFixed(2)} MiB
            {preview.family && (' · ' + { inno: 'Inno Setup', nsis: 'NSIS', installshield: 'InstallShield', installshield_basic_msi: 'InstallShield Basic MSI' }[preview.family])}</p>
          <StatusBadge tone={preview.signature === 'verified' ? 'success' : 'warning'}>
            {preview.signature === 'verified' ? t('Подпись подтверждена', 'Verified signature') : t('Подпись не подтверждена', 'Unverified signature')}
          </StatusBadge>
        </div>
        <Field name="name" label={t('Название', 'Name')} required maxLength={160} defaultValue={preview.name ?? preview.filename.replace(/\.[^.]+$/, '')} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Field name="publisher" label={t('Производитель', 'Publisher')} required maxLength={160} defaultValue={preview.publisher ?? ''} />
          <Field name="version" label={t('Версия', 'Version')} required maxLength={80}
            pattern={String.raw`[A-Za-z0-9][A-Za-z0-9._+\-]*`} defaultValue={preview.version?.replace(/,\s*/g, '.') ?? ''} />
        </div>
        <Field name="category" label={t('Категория', 'Category')} maxLength={160} />
        <details className="rounded-lg border border-border p-3">
          <summary className="cursor-pointer font-medium">{t('Дополнительно', 'Advanced')}</summary>
          <div className="mt-3 grid gap-3">
            <code className="break-all text-xs">SHA-256 {preview.sha256}</code>
            <label className="grid gap-2 text-sm">{t('Описание', 'Description')}<textarea name="description" className="input" maxLength={4000} /></label>
            <label className="grid gap-2 text-sm">{t('Аргументы установки, по одному в строке', 'Installation arguments, one per line')}
              <textarea name="install" className="input" defaultValue={preview.install_args.join('\n')} maxLength={12000} />
            </label>
            <label className="grid gap-2 text-sm">{t('Аргументы удаления, по одному в строке', 'Removal arguments, one per line')}
              <textarea name="uninstall" className="input" defaultValue={preview.uninstall_args?.join('\n')} maxLength={12000} />
            </label>
            <label className="text-sm"><input name="remove" type="checkbox" defaultChecked={preview.uninstall_args !== null} /> {t('Разрешить удаление', 'Allow removal')}</label>
            <p className="text-sm text-muted-foreground">{preview.product_code ? `MSI ProductCode ${preview.product_code}`
              : t('По умолчанию проверяются имя и версия в реестре Windows.', 'Detection uses the Windows registry name and version by default.')}</p>
            <label className="text-sm"><input type="checkbox" checked={overrideDetection} onChange={event => setOverrideDetection(event.target.checked)} /> {t('Указать своё правило обнаружения', 'Set a custom detection rule')}</label>
            {overrideDetection && <DetectionFields index={0} t={t} />}
          </div>
        </details>
        {preview.installer === 'exe' && <p className="text-sm text-muted-foreground">
          {preview.install_args.length
            ? t('Проверь предложенные аргументы установки в разделе «Дополнительно».', 'Review the suggested installation arguments under Advanced.')
            : t('Для этого EXE параметры тихой установки не определены. Уточни их у производителя.', 'Silent installation arguments could not be determined. Check with the publisher.')}
        </p>}
        <FormError message={create.error ? errorMessage(create.error, t) : null} />
        <div className="flex flex-wrap gap-2">
          <Action type="submit" disabled={create.isPending}>{t('Сохранить программу', 'Save program')}</Action>
          <Action secondary type="button" disabled={create.isPending} onClick={() => setPreview(undefined)}>{t('Выбрать другой файл', 'Choose another file')}</Action>
        </div>
      </form>}
    </div>
  </Dialog>
}

export function PackageCatalog({ session, t, deploy }: Props & { deploy: (preset: DeploymentPreset) => void }) {
  const client = useQueryClient()
  const [selected, setSelected] = useState<string>()
  const [picked, setPicked] = useState(new Map<string, Product>())
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  const [offset, setOffset] = useState(0)
  const [sort, setSort] = useState<'name' | 'publisher'>('name')
  const [direction, setDirection] = useState<'asc' | 'desc'>('asc')
  const [open, setOpen] = useState(false)
  const query = useQuery({
    queryKey: ['packages', term, offset, sort, direction], enabled: !selected,
    queryFn: () => api<{ items: Product[]; total: number }>(`/packages?${new URLSearchParams({ q: term, offset: String(offset), limit: String(pageSize), sort, direction })}`),
  })
  if (selected) return <ProductDetails key={selected} id={selected} selectedPackage={setSelected} back={() => setSelected(undefined)} session={session} t={t} deploy={deploy} />
  return <Panel>
    <SectionTitle title={t('Каталог программ', 'Software catalog')} actions={session.user.role !== 'viewer' &&
      <Action onClick={() => setOpen(true)}><Plus className="size-4" aria-hidden />{t('Добавить программу', 'Add program')}</Action>} />
    <form className="mb-4 flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); setTerm(search.trim()); setOffset(0) }}>
      <Field label={t('Название или издатель', 'Name or publisher')} value={search} maxLength={160} onChange={event => setSearch(event.target.value)} />
      <label className="grid gap-2 text-sm">{t('Сортировка', 'Sort by')}
        <select className="input" value={sort} onChange={event => { setOffset(0); setSort(event.target.value === 'publisher' ? 'publisher' : 'name') }}>
          <option value="name">{t('Название', 'Name')}</option><option value="publisher">{t('Издатель', 'Publisher')}</option>
        </select>
      </label>
      <label className="grid gap-2 text-sm">{t('Порядок', 'Order')}
        <select className="input" value={direction} onChange={event => { setOffset(0); setDirection(event.target.value === 'desc' ? 'desc' : 'asc') }}>
          <option value="asc">{t('По возрастанию', 'Ascending')}</option><option value="desc">{t('По убыванию', 'Descending')}</option>
        </select>
      </label>
      <Action secondary type="submit">{t('Поиск', 'Search')}</Action>
    </form>
    {query.isPending && <LoadingSkeleton label={t('Загрузка каталога', 'Loading catalog')} />}
    <FormError message={query.error && errorMessage(query.error, t)} />
    {query.data?.items.length === 0 && <EmptyState icon={Package} title={term ? t('Ничего не найдено', 'No results') : t('Программ пока нет', 'No programs yet')} />}
    {picked.size > 0 && <div className="mb-3 flex gap-2">
      <Action onClick={() => {
        const programs = [...picked.values()]
        setPicked(new Map())
        if (programs.length === 1) deploy({ packageId: programs[0].id, productName: programs[0].name })
        else deploy({ programs })
      }}>{t('Установить выбранные', 'Install selected')} ({picked.size})</Action>
      <Action secondary onClick={() => setPicked(new Map())}>{t('Снять выбор', 'Clear selection')}</Action>
    </div>}
    {!!query.data?.items.length && <div className="overflow-x-auto"><table className="w-full text-left text-sm">
      <thead className="border-b border-border text-muted-foreground">
        <tr>{session.user.role !== 'viewer' && <th scope="col" className="px-2"><span className="sr-only">{t('Выбор', 'Selection')}</span></th>}
          <th scope="col" className="px-3 py-2">{t('Программа', 'Program')}</th>
          <th scope="col" className="px-3 py-2">{t('Производитель', 'Publisher')}</th>
          <th scope="col" className="px-3 py-2">{t('Категория', 'Category')}</th>
          {session.user.role !== 'viewer' && <th scope="col" className="px-2"><span className="sr-only">{t('Действие', 'Action')}</span></th>}</tr>
      </thead>
      <tbody className="divide-y divide-border">{query.data.items.map(item => <tr key={item.id} className="hover:bg-muted/40">
        {session.user.role !== 'viewer' && <td className="px-2">{item.can_deploy && <input type="checkbox"
          aria-label={t('Выбрать программу', 'Select program') + ' ' + item.name}
          checked={picked.has(item.id)} disabled={picked.size >= 20 && !picked.has(item.id)}
          onChange={event => {
            const next = new Map(picked)
            if (event.target.checked) next.set(item.id, item)
            else next.delete(item.id)
            setPicked(next)
          }} />}</td>}
        <td className="px-3 py-3"><button className="break-words text-left font-medium text-primary hover:underline"
          onClick={() => setSelected(item.id)} type="button">{item.name}</button></td>
        <td className="px-3 py-3">{item.publisher}</td><td className="px-3 py-3">{item.category || '—'}</td>
        {session.user.role !== 'viewer' && <td className="px-2 text-right">{item.can_deploy &&
          <Action secondary onClick={() => deploy({ packageId: item.id, productName: item.name })}>{t('Установить', 'Install')}</Action>}</td>}
      </tr>)}</tbody>
    </table></div>}
    {(offset > 0 || (query.data?.total ?? 0) > pageSize) && <div className="mt-4 flex flex-wrap gap-2">
      <Action secondary disabled={!offset} onClick={() => setOffset(offset - pageSize)}>{t('Предыдущая', 'Previous')}</Action>
      <Action secondary disabled={offset + pageSize >= (query.data?.total ?? 0)} onClick={() => setOffset(offset + pageSize)}>{t('Следующая', 'Next')}</Action>
    </div>}
    {open && <IntakeDialog t={t} session={session} close={() => setOpen(false)} saved={record => {
      setOpen(false); setSelected(record.id); void client.invalidateQueries({ queryKey: ['packages'] })
    }} />}
  </Panel>
}
