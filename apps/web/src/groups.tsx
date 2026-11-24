import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, type Session } from './api'
import { Dialog } from './components/ui/dialog'
import { ConfirmDialog, EmptyState, LoadingSkeleton } from './design'
import { Action, Field, FormError, errorMessage, type Translate } from './ui'

export interface GroupMember { id: string; hostname: string; agent_version: string }
export interface DeviceGroup { id: string; name: string; devices: GroupMember[] }

export function useDeviceGroups(enabled = true) {
  return useQuery({ queryKey: ['device-groups'], queryFn: () => api<DeviceGroup[]>('/device-groups'), enabled })
}

export function DeviceGroupsDialog({ session, t, selected, close }: {
  session: Session; t: Translate; selected: Map<string, string>; close: () => void
}) {
  const groups = useDeviceGroups()
  const client = useQueryClient()
  const [editing, setEditing] = useState<DeviceGroup>()
  const [form, setForm] = useState(false)
  const [removing, setRemoving] = useState<DeviceGroup>()
  const [useSelected, setUseSelected] = useState(false)
  const [notice, setNotice] = useState('')
  const writable = session.user.role !== 'viewer'
  const csrf = session.csrf_token
  const save = useMutation({
    mutationFn: ({ name, device_ids }: { name: string; device_ids: string[] }) =>
      api<DeviceGroup>(editing ? '/device-groups/' + editing.id : '/device-groups',
        { method: editing ? 'PUT' : 'POST', body: { name, device_ids }, csrf }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['device-groups'] })
      setForm(false)
      setNotice(t('Группа сохранена.', 'Group saved.'))
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api<void>('/device-groups/' + id, { method: 'DELETE', csrf }),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['device-groups'] }); setNotice(t('Группа удалена.', 'Group deleted.')) },
  })
  function start(group?: DeviceGroup) {
    setNotice('')
    save.reset()
    setEditing(group)
    setUseSelected(!group)
    setForm(true)
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    save.mutate({ name: String(data.get('name')).trim(),
      device_ids: useSelected ? [...selected.keys()] : editing?.devices.map(device => device.id) ?? [] })
  }
  return <>
    <Dialog title={t('Группы устройств', 'Device groups')} close={close} closeLabel={t('Закрыть', 'Close')}>
      <div className="grid gap-3">
        {notice && <p role="status" className="text-sm">{notice}</p>}
        <FormError message={(groups.error || remove.error) && errorMessage(groups.error || remove.error, t)} />
        {groups.isPending ? <LoadingSkeleton label={t('Загрузка групп', 'Loading groups')} />
          : !groups.data?.length ? <EmptyState title={t('Групп пока нет', 'No groups yet')} />
          : <ul className="divide-y divide-border">{groups.data.map(group => <li key={group.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <div><p className="font-medium">{group.name}</p><p className="text-sm text-muted-foreground">
              {t('Устройств', 'Devices')} {group.devices.length}</p></div>
            {writable && <div className="flex gap-2">
              <Action secondary onClick={() => start(group)}>{t('Редактировать', 'Edit')}</Action>
              <Action secondary onClick={() => { remove.reset(); setRemoving(group) }}>{t('Удалить', 'Delete')}</Action>
            </div>}
          </li>)}</ul>}
        {writable && !form && <Action onClick={() => start()}>{t('Создать группу', 'Create group')}</Action>}
        {writable && form && <form className="grid gap-3 rounded-lg border border-border p-3" key={editing?.id ?? 'new'} onSubmit={submit}>
          <Field name="name" label={t('Название группы', 'Group name')} maxLength={160} required defaultValue={editing?.name} />
          {editing ? <label className="text-sm"><input type="checkbox" checked={useSelected} onChange={event => setUseSelected(event.target.checked)} />
            {' '}{t('Заменить состав выбранными устройствами', 'Replace membership with selected devices')}</label> : null}
          <p className="text-sm text-muted-foreground">{t('В составе устройств', 'Devices in this group')} {useSelected ? selected.size : editing?.devices.length}</p>
          <FormError message={save.error && errorMessage(save.error, t)} />
          <div className="flex gap-2">
            <Action type="submit" disabled={save.isPending || (useSelected && selected.size > 100)}>{t('Сохранить', 'Save')}</Action>
            <Action type="button" secondary onClick={() => setForm(false)}>{t('Отмена', 'Cancel')}</Action>
          </div>
        </form>}
      </div>
    </Dialog>
    {removing && <ConfirmDialog title={t('Удалить группу?', 'Delete group?')}
      description={t('Устройства и уже созданные задания сохранятся.', 'Devices and existing jobs are retained.')}
      labels={{ close: t('Закрыть', 'Close'), cancel: t('Отмена', 'Cancel'), confirm: t('Удалить', 'Delete') }}
      close={() => setRemoving(undefined)} confirm={() => { remove.mutate(removing.id); setRemoving(undefined) }} />}
  </>
}
