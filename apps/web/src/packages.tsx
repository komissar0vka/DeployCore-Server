import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Package, Plus } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import type { DeploymentPreset } from './deployments'
import { api, type Session } from './api'
import { Dialog } from './components/ui/dialog'
import { ConfirmDialog, EmptyState, LoadingSkeleton, SectionTitle, StatusBadge } from './design'
import { Action, Field, FormError, Panel, detectionLabel, errorMessage, type Translate } from './ui'

interface ProductFields { name: string; publisher: string; description: string }
interface Product extends ProductFields { id: string }
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
interface Version extends VersionInput { id: string; approved_at: string | null; approval_kind: 'authenticode' | 'manual' | null; artifact: Artifact | null }
interface Props { session: Session; t: Translate }
const pageSize = 25

function ProductDialog({ product, close, save, pending, error, t }: {
  product?: Product; close: () => void; save: (body: ProductFields) => void; pending: boolean; error: unknown; t: Translate
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    save({ name: String(data.get('name')), publisher: String(data.get('publisher')), description: String(data.get('description')) })
  }
  return <Dialog title={product ? t('Редактировать программу', 'Edit program') : t('Новая программа', 'New program')}
    close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={submit}>
      <Field name="name" label={t('Название', 'Name')} maxLength={160} required defaultValue={product?.name} />
      <Field name="publisher" label={t('Издатель', 'Publisher')} maxLength={160} required defaultValue={product?.publisher} />
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

function DetectionFields({ index, t }: { index: number; t: Translate }) {
  const [kind, setKind] = useState<DetectionLeaf['kind']>('registry_software')
  return <fieldset className="grid gap-3 rounded border border-border p-3">
    <label className="grid gap-2 text-sm">{t('Тип правила', 'Rule type')}
      <select className="input" name={`ruleKind${index}`} value={kind} onChange={event => setKind(event.target.value as DetectionLeaf['kind'])}>
        <option value="registry_software">{t('Имя и версия в реестре', 'Registry name and version')}</option>
        <option value="msi_product">MSI ProductCode</option>
        <option value="file_exists">{t('Наличие файла', 'File exists')}</option>
        <option value="file_version">{t('Версия файла', 'File version')}</option>
      </select>
    </label>
    {kind === 'msi_product' && <Field name={`productCode${index}`} label="MSI ProductCode" required maxLength={38} />}
    {kind === 'registry_software' && <Field name={`display${index}`} label={t('Имя в реестре', 'Registry display name')} required maxLength={160} />}
    {(kind === 'file_exists' || kind === 'file_version') && <Field name={`filePath${index}`} label={t('Абсолютный путь к файлу', 'Absolute file path')} required maxLength={240} />}
    {(kind === 'registry_software' || kind === 'file_version') && <Field key={kind} name={`detectedVersion${index}`}
      label={kind === 'file_version' ? t('Версия файла', 'File version') : t('Версия в реестре', 'Registry version')} required maxLength={120} />}
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

function VersionDialog({ t, close, save, pending, error }: {
  t: Translate; close: () => void; save: (body: VersionInput) => void; pending: boolean; error: unknown
}) {
  const [group, setGroup] = useState<'single' | 'all' | 'any'>('single')
  const [ruleCount, setRuleCount] = useState(2)
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
  return <Dialog title={t('Новая версия', 'New version')} close={close} closeLabel={t('Закрыть', 'Close')}>
    <form className="grid gap-3" onSubmit={submit}>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field name="version" label={t('Версия', 'Version')} required maxLength={80} />
        <label className="grid gap-2 text-sm">{t('Тип', 'Type')}<select className="input" name="installer" aria-label={t('Тип', 'Type')}><option value="msi">MSI</option><option value="exe">EXE</option></select></label>
        <label className="grid gap-2 text-sm">{t('Архитектура', 'Architecture')}<select className="input" name="architecture" aria-label={t('Архитектура', 'Architecture')}><option>x64</option><option>x86</option></select></label>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field name="build" label={t('Мин. сборка Windows', 'Min. Windows build')} type="number" min={1} max={2147483647} />
        <Field name="timeout" label={t('Таймаут, с', 'Timeout, s')} type="number" min={1} max={86400} required defaultValue={1800} />
      </div>
      <Field name="codes" label={t('Допустимые коды через запятую', 'Accepted exit codes, comma-separated')}
        pattern="[0-9]+(, *[0-9]+)*" required defaultValue="0, 3010" />
      <label className="grid gap-2 text-sm">{t('Аргументы установки, по одному в строке', 'Installation arguments, one per line')}
        <textarea className="input" name="install" maxLength={12000} />
      </label>
      <label className="grid gap-2 text-sm">{t('Аргументы удаления, по одному в строке', 'Removal arguments, one per line')}
        <textarea className="input" name="uninstall" maxLength={12000} />
      </label>
      <label className="text-sm"><input name="remove" type="checkbox" /> {t('Разрешить удаление', 'Allow removal')}</label>
      <label className="text-sm"><input name="reboot" type="checkbox" /> {t('Требуется перезагрузка', 'Restart required')}</label>
      <label className="grid gap-2 text-sm">{t('Правило обнаружения', 'Detection rule')}
        <select className="input" value={group} onChange={event => setGroup(event.target.value as typeof group)}>
          <option value="single">{t('Одно правило', 'Single rule')}</option>
          <option value="all">{t('Все правила', 'All rules')}</option>
          <option value="any">{t('Любое правило', 'Any rule')}</option>
        </select>
      </label>
      {Array.from({ length: group === 'single' ? 1 : ruleCount }, (_, index) => <DetectionFields key={index} index={index} t={t} />)}
      {group !== 'single' && <div className="flex flex-wrap gap-2">
        <Action type="button" secondary disabled={ruleCount >= 8} onClick={() => setRuleCount(ruleCount + 1)}>{t('Добавить правило', 'Add rule')}</Action>
        <Action type="button" secondary disabled={ruleCount <= 2} onClick={() => setRuleCount(ruleCount - 1)}>{t('Удалить последнее правило', 'Remove last rule')}</Action>
      </div>}
      <FormError message={error ? errorMessage(error, t) : null} />
      <Action type="submit" disabled={pending}>{t('Добавить версию', 'Add version')}</Action>
    </form>
  </Dialog>
}

function UploadForm({ path, installer, csrf, t, uploaded }: {
  path: string; installer: string; csrf: string; t: Translate; uploaded: () => void
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
      await api<Artifact>(`${path}?${new URLSearchParams({ filename: selected.name })}`, {
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
      <Action type="submit" disabled={!!controller}>{t('Загрузить и проверить', 'Upload and verify')}</Action>
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
    refetchInterval: query => query.state.data?.status === 'completed' || query.state.data?.status === 'expired' ? false : 2000,
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

function ProductDetails({ id, back, session, t, deploy }: Props & { id: string; back: () => void; deploy: (preset: DeploymentPreset) => void }) {
  const client = useQueryClient()
  const path = '/packages/' + id
  const query = useQuery({ queryKey: ['package', id], queryFn: () => api<Product & { versions: Version[] }>(path) })
  const [modal, setModal] = useState<'edit' | 'version' | 'archive' | null>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [manual, setManual] = useState<{ version: string; artifact: Artifact } | null>(null)
  const writable = session.user.role !== 'viewer'
  const csrf = session.csrf_token
  function updated() {
    void client.invalidateQueries({ queryKey: ['package', id] })
    void client.invalidateQueries({ queryKey: ['packages'] })
  }
  const edit = useMutation({ mutationFn: (body: ProductFields) => api<Product>(path, { method: 'PATCH', body, csrf }),
    onSuccess: () => { updated(); setModal(null) } })
  const add = useMutation({ mutationFn: (body: VersionInput) => api<Version>(path + '/versions', { method: 'POST', body, csrf }),
    onSuccess: () => { updated(); setModal(null) } })
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
    <Action secondary onClick={back}>{t('К каталогу', 'Back to catalog')}</Action>
    {query.isPending && <LoadingSkeleton label={t('Загрузка программы', 'Loading program')} />}
    <FormError message={(query.error || archive.error || approval.error) && errorMessage(query.error || archive.error || approval.error, t)} />
    {product && <Panel>
      <SectionTitle title={product.name} description={product.publisher} actions={writable && <div className="flex flex-wrap gap-2">
        <Action secondary onClick={() => { edit.reset(); setModal('edit') }}>{t('Редактировать', 'Edit')}</Action>
        <Action secondary onClick={() => setModal('archive')} disabled={archive.isPending}>{t('Архивировать', 'Archive')}</Action>
        <Action onClick={() => { add.reset(); setModal('version') }}>{t('Новая версия', 'New version')}</Action>
      </div>} />
      {product.description && <p className="mb-3 break-words text-sm text-muted-foreground">{product.description}</p>}
      {!product.versions.length && <EmptyState title={t('Версий пока нет', 'No versions yet')} />}
      <div className="grid gap-3">
        {product.versions.map(version => {
          const artifactPath = `${path}/versions/${version.id}/artifact`
          return <details key={version.id} className="rounded-xl border border-border px-3 py-2.5">
            <summary className="cursor-pointer text-sm"><strong>{version.version}</strong> · {version.installer.toUpperCase()} {version.architecture}
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
              {writable && <div><Action secondary onClick={() => setPreview(version.id)}>{t('Проверить обнаружение', 'Preview detection')}</Action></div>}
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
    {preview && <DetectionPreviewDialog version={preview} csrf={csrf} t={t} close={() => setPreview(null)} />}
    {manual && <ManualApprovalDialog artifact={manual.artifact} t={t} close={() => setManual(null)}
      save={sha256 => manualApproval.mutate({ version: manual.version, sha256 })}
      pending={manualApproval.isPending} error={manualApproval.error} />}
    {modal === 'edit' && product && <ProductDialog product={product} t={t} close={() => setModal(null)}
      save={body => edit.mutate(body)} pending={edit.isPending} error={edit.error} />}
    {modal === 'version' && <VersionDialog t={t} close={() => setModal(null)}
      save={body => add.mutate(body)} pending={add.isPending} error={add.error} />}
    {modal === 'archive' && <ConfirmDialog title={t('Архивировать программу?', 'Archive program?')}
      description={t('Программа исчезнет из каталога. Версии и установщики сохранятся.', 'The program is hidden. Versions and files are retained.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Архивировать', 'Archive') }}
      close={() => setModal(null)} confirm={() => { setModal(null); archive.mutate() }} />}
  </div>
}

export function PackageCatalog({ session, t, deploy }: Props & { deploy: (preset: DeploymentPreset) => void }) {
  const client = useQueryClient()
  const [selected, setSelected] = useState<string>()
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('')
  const [offset, setOffset] = useState(0)
  const [open, setOpen] = useState(false)
  const query = useQuery({
    queryKey: ['packages', term, offset], enabled: !selected,
    queryFn: () => api<{ items: Product[]; total: number }>(`/packages?${new URLSearchParams({ q: term, offset: String(offset), limit: String(pageSize) })}`),
  })
  const create = useMutation({
    mutationFn: (body: ProductFields) => api<Product>('/packages', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: record => { setOpen(false); setSelected(record.id); void client.invalidateQueries({ queryKey: ['packages'] }) },
  })
  if (selected) return <ProductDetails id={selected} back={() => setSelected(undefined)} session={session} t={t} deploy={deploy} />
  return <Panel>
    <SectionTitle title={t('Каталог программ', 'Software catalog')} actions={session.user.role !== 'viewer' &&
      <Action onClick={() => { create.reset(); setOpen(true) }}><Plus className="size-4" aria-hidden />{t('Новая программа', 'New program')}</Action>} />
    <form className="mb-4 flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); setTerm(search.trim()); setOffset(0) }}>
      <Field label={t('Название или издатель', 'Name or publisher')} value={search} maxLength={160} onChange={event => setSearch(event.target.value)} />
      <Action secondary type="submit">{t('Поиск', 'Search')}</Action>
    </form>
    {query.isPending && <LoadingSkeleton label={t('Загрузка каталога', 'Loading catalog')} />}
    <FormError message={query.error && errorMessage(query.error, t)} />
    {query.data?.items.length === 0 && <EmptyState icon={Package} title={term ? t('Ничего не найдено', 'No results') : t('Программ пока нет', 'No programs yet')} />}
    {!!query.data?.items.length && <ul className="divide-y divide-border">{query.data.items.map(item => <li key={item.id} className="py-3">
      <button className="break-all text-left font-medium text-primary hover:underline" onClick={() => setSelected(item.id)} type="button">{item.name}</button>
      <p className="break-words text-sm text-muted-foreground">{item.publisher}</p>
    </li>)}</ul>}
    {(offset > 0 || (query.data?.total ?? 0) > pageSize) && <div className="mt-4 flex flex-wrap gap-2">
      <Action secondary disabled={!offset} onClick={() => setOffset(offset - pageSize)}>{t('Предыдущая', 'Previous')}</Action>
      <Action secondary disabled={offset + pageSize >= (query.data?.total ?? 0)} onClick={() => setOffset(offset + pageSize)}>{t('Следующая', 'Next')}</Action>
    </div>}
    {open && <ProductDialog t={t} close={() => setOpen(false)} save={body => create.mutate(body)} pending={create.isPending} error={create.error} />}
  </Panel>
}
