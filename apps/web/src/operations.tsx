import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { api, pollEvery, type Session } from './api'
import { ConfirmDialog, SectionTitle } from './design'
import { Action, FormError, Panel, errorMessage, type Translate } from './ui'

type Stage = 'queued' | 'running' | 'checking' | 'downloading' | 'loading_images' | 'backing_up' | 'applying' | 'rolling_back' | 'completed' | 'failed' | 'interrupted'
type Operation = { action: 'backup' } | { action: 'update'; channel: 'stable' | 'beta'; version: string }
interface State {
  available: boolean
  status: { id: string; action: Operation['action']; stage: Stage } | null
  backups: { id: string; bytes: number; created_at: string }[]
}

const finished = new Set(['completed', 'failed', 'interrupted'])

export function HostOperations({ session, t, update }: {
  session: Session; t: Translate; update?: Extract<Operation, { action: 'update' }>
}) {
  const [confirm, setConfirm] = useState(false)
  const query = useQuery({ queryKey: ['operations'], queryFn: () => api<State>('/operations'), refetchInterval: pollEvery(2500) })
  const submit = useMutation({
    mutationFn: (body: Operation) => api('/operations', { method: 'POST', body, csrf: session.csrf_token }),
    onSuccess: () => { void query.refetch() },
  })
  const info = query.data
  const active = submit.isPending || !!info?.status && !finished.has(info.status.stage)
  const titles: Record<Stage, string> = {
    queued: t('В очереди', 'Queued'), running: t('Начата', 'Started'), checking: t('Проверка выпуска', 'Checking release'),
    downloading: t('Загрузка выпуска', 'Downloading release'), loading_images: t('Загрузка готовых образов из архива', 'Loading bundled images'), backing_up: t('Резервное копирование', 'Backing up'),
    applying: t('Запуск новой версии', 'Starting the new version'), rolling_back: t('Восстановление прежней версии', 'Rolling back'),
    completed: t('Завершена', 'Completed'), failed: t('Ошибка операции', 'Operation failed'),
    interrupted: t('Операция прервана', 'Operation interrupted'),
  }
  return <Panel>
    <SectionTitle title={update ? t('Обновление Server', 'Server update') : t('Резервные копии', 'Backups')} />
    <FormError message={(query.error || submit.error) && errorMessage(query.error || submit.error, t)} />
    {info?.available === false && <p className="text-sm text-muted-foreground">{t('Служба операций хоста недоступна.', 'Host operations are unavailable.')}</p>}
    {info?.status && <p className="mb-2 text-sm" role="status">{titles[info.status.stage]}</p>}
    {info?.available && (update ?
      <Action disabled={active} onClick={() => setConfirm(true)}>{t('Обновить Server', 'Update Server')} · {update.version}</Action>
      : <Action disabled={active} onClick={() => submit.mutate({ action: 'backup' })}>{t('Создать копию', 'Create backup')}</Action>)}
    {!update && !!info?.backups.length && <ul className="mt-3 divide-y divide-border text-sm">{info.backups.map(backup =>
      <li key={backup.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
        <span>{new Date(backup.created_at).toLocaleString(t('ru', 'en'))} · {(backup.bytes / 1048576).toFixed(1)} МиБ</span>
        <a className="text-primary underline" href={'/api/v1/operations/backups/' + backup.id} download>{t('Скачать', 'Download')}</a>
      </li>)}</ul>}
    {confirm && update && <ConfirmDialog title={t('Обновить Server?', 'Update Server?')}
      description={t('Панель временно станет недоступна. Перед обновлением будет создана проверенная копия.', 'The console will be temporarily unavailable. A verified backup is made before updating.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Обновить', 'Update') }}
      close={() => setConfirm(false)} confirm={() => { setConfirm(false); submit.mutate(update) }} />}
  </Panel>
}
