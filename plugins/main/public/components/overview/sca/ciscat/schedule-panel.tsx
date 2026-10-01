/*
 * CIS-CAT schedules: one-shot, monthly (day N or N days before the end of the
 * month) and weekly runs, in waves, plus "Run now". Job times are the
 * manager's local time; the scheduler publishes its time zone.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useMemo, useState } from 'react';
import {
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiButtonIcon,
  EuiCallOut,
  EuiComboBox,
  EuiConfirmModal,
  EuiFieldNumber,
  EuiFieldText,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiForm,
  EuiFormRow,
  EuiHealth,
  EuiRadioGroup,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import {
  CISCAT_LISTS,
  Job,
  ListRecords,
  newJobKey,
  newRequestKey,
  validateJob,
} from '../../../../../common/ciscat/store';
import { getToasts } from '../../../../kibana-services';
import { describeJob, describeTargets } from './lib/composer';
import { addRequest, writeList } from './lib/lists-api';
import { masterTime } from './lib/status';
import type { CiscatData } from './ciscat-management';

const WEEKDAYS = [
  'Monday',
  'Tuesday',
  'Wednesday',
  'Thursday',
  'Friday',
  'Saturday',
  'Sunday',
];

const STATE_COLOR: Record<string, string> = {
  ok: 'success',
  error: 'danger',
  running: 'primary',
  starting: 'primary',
};

const validJobs = (records: ListRecords) =>
  Object.entries(records).reduce((acc, [key, rec]) => {
    if (!key.startsWith('_')) {
      try {
        acc[key] = validateJob(rec);
      } catch {
        // invalid jobs are reported by the manager
      }
    }
    return acc;
  }, {} as Record<string, Job>);

const formatDate = (date?: Date) => (date ? date.toLocaleString() : '—');

interface JobFlyoutProps {
  initial?: Job;
  runNow?: boolean;
  osKeys: string[];
  onClose: () => void;
  onSave: (job: Job) => void;
}

const today = () => new Date().toISOString().slice(0, 10);

const JobFlyout = ({
  initial,
  runNow,
  osKeys,
  onClose,
  onSave,
}: JobFlyoutProps) => {
  const [label, setLabel] = useState(initial?.label || '');
  const [type, setType] = useState<Job['type']>(initial?.type || 'monthly');
  const [date, setDate] = useState((initial?.at || '').slice(0, 10) || today());
  const [time, setTime] = useState(
    initial?.time || (initial?.at || '').slice(11, 16) || '22:00',
  );
  const [fromEnd, setFromEnd] = useState((initial?.day ?? 1) < 0);
  const [day, setDay] = useState(Math.abs(initial?.day ?? 1));
  const [weekday, setWeekday] = useState(initial?.weekday ?? 5);
  const [targets, setTargets] = useState<Array<{ label: string }>>(
    (initial?.targets || ['*']).map(t => ({
      label: t === '*' ? 'All active OS' : t,
    })),
  );
  const [waveSize, setWaveSize] = useState(initial?.wave_size ?? 50);
  const [pauseMin, setPauseMin] = useState(
    Math.round((initial?.wave_pause_s ?? 300) / 60),
  );
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState('');

  const submit = () => {
    try {
      const chosen = targets.map(t =>
        t.label === 'All active OS' ? '*' : t.label,
      );
      const job = validateJob({
        type: runNow ? 'once' : type,
        at: runNow ? '2000-01-01T00:00' : `${date}T${time}`,
        time,
        day: fromEnd ? -day : day,
        weekday,
        targets: chosen.includes('*') ? ['*'] : chosen,
        wave_size: Number(waveSize),
        wave_pause_s: Number(pauseMin) * 60,
        enabled,
        label,
      });
      onSave(job);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <EuiFlyout onClose={onClose} size='s' ownFocus>
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size='s'>
          <h3>
            {runNow && 'Run CIS-CAT now'}
            {!runNow && (initial ? 'Edit schedule' : 'New schedule')}
          </h3>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <EuiForm component='form' onSubmit={e => e.preventDefault()}>
          <EuiFormRow label='Name'>
            <EuiFieldText
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder={runNow ? 'Run now' : 'Month-end assessment'}
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow label='When'>
              <EuiRadioGroup
                idSelected={`ciscat-type-${type}`}
                onChange={id =>
                  setType(id.replace('ciscat-type-', '') as Job['type'])
                }
                options={[
                  { id: 'ciscat-type-once', label: 'Once' },
                  { id: 'ciscat-type-monthly', label: 'Every month' },
                  { id: 'ciscat-type-weekly', label: 'Every week' },
                ]}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'once' && (
            <EuiFormRow label='Date' helpText='YYYY-MM-DD'>
              <EuiFieldText
                value={date}
                onChange={e => setDate(e.target.value)}
              />
            </EuiFormRow>
          )}
          {!runNow && type === 'monthly' && (
            <>
              <EuiFormRow label='Day'>
                <EuiRadioGroup
                  idSelected={fromEnd ? 'ciscat-from-end' : 'ciscat-day'}
                  onChange={id => setFromEnd(id === 'ciscat-from-end')}
                  options={[
                    { id: 'ciscat-day', label: 'Day of the month' },
                    {
                      id: 'ciscat-from-end',
                      label: 'Days before the end of the month',
                    },
                  ]}
                />
              </EuiFormRow>
              <EuiFormRow
                label={
                  fromEnd
                    ? 'Day from the end (1 = last day)'
                    : 'Day of the month'
                }
                helpText={
                  fromEnd
                    ? '1..28'
                    : '1..31; months without that day use their last day'
                }
              >
                <EuiFieldNumber
                  min={1}
                  max={fromEnd ? 28 : 31}
                  value={day}
                  onChange={e => setDay(Number(e.target.value))}
                />
              </EuiFormRow>
            </>
          )}
          {!runNow && type === 'weekly' && (
            <EuiFormRow label='Day of the week'>
              <EuiSelect
                options={WEEKDAYS.map((text, value) => ({ value, text }))}
                value={weekday}
                onChange={e => setWeekday(Number(e.target.value))}
              />
            </EuiFormRow>
          )}
          {!runNow && (
            <EuiFormRow label='Time' helpText="HH:MM, manager's local time">
              <EuiFieldText
                value={time}
                onChange={e => setTime(e.target.value)}
              />
            </EuiFormRow>
          )}
          <EuiFormRow label='Operating systems'>
            <EuiComboBox
              options={[
                { label: 'All active OS' },
                ...osKeys.map(label => ({ label })),
              ]}
              selectedOptions={targets}
              onChange={setTargets}
            />
          </EuiFormRow>
          <EuiFormRow label='Agents per wave'>
            <EuiFieldNumber
              min={1}
              value={waveSize}
              onChange={e => setWaveSize(Number(e.target.value))}
            />
          </EuiFormRow>
          <EuiFormRow label='Pause between waves (minutes)'>
            <EuiFieldNumber
              min={0}
              value={pauseMin}
              onChange={e => setPauseMin(Number(e.target.value))}
            />
          </EuiFormRow>
          {!runNow && (
            <EuiFormRow>
              <EuiSwitch
                label='Enabled'
                checked={enabled}
                onChange={e => setEnabled(e.target.checked)}
              />
            </EuiFormRow>
          )}
        </EuiForm>
        {error && (
          <>
            <EuiSpacer size='s' />
            <EuiCallOut color='danger' size='s' title={error} />
          </>
        )}
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <EuiFlexGroup justifyContent='spaceBetween'>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty onClick={onClose}>Cancel</EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButton fill onClick={submit} data-test-subj='ciscat-save-job'>
              {runNow ? 'Run now' : 'Save'}
            </EuiButton>
          </EuiFlexItem>
        </EuiFlexGroup>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
};

interface Props {
  data: CiscatData;
  user: string;
  onSaved: () => void;
}

export const SchedulePanel = ({ data, user, onSaved }: Props) => {
  const jobs = useMemo(() => validJobs(data.schedule.records), [data.schedule]);
  const [editing, setEditing] = useState<{ key: string; job?: Job }>();
  const [runNow, setRunNow] = useState(false);
  const [deleting, setDeleting] = useState<string>();
  const osKeys = Object.keys(data.oskeys)
    .filter(k => data.oskeys[k].active)
    .sort();
  const scheduler = data.status.scheduler || {};
  const offset = scheduler.utc_offset;

  const persist = async (next: Record<string, Job>, message: string) => {
    try {
      await writeList(CISCAT_LISTS.schedule, next, data.schedule.raw);
      getToasts().addSuccess({ title: message });
      onSaved();
      return true;
    } catch (e) {
      getToasts().addDanger({
        title: 'Schedule not saved',
        text: (e as Error).message,
      });
      return false;
    }
  };

  const items = Object.entries(jobs)
    .map(([key, job]) => ({
      key,
      job,
      status: data.status[`job-${key}`] || {},
    }))
    .sort((a, b) => (a.job.label || a.key).localeCompare(b.job.label || b.key));

  const columns = [
    {
      name: 'Schedule',
      render: ({ key, job }: (typeof items)[number]) => (
        <span>
          <strong>{job.label || key}</strong>
          <br />
          <EuiText size='xs' color='subdued'>
            {describeJob(job)}
          </EuiText>
        </span>
      ),
    },
    {
      name: 'Targets',
      render: ({ job }: (typeof items)[number]) => describeTargets(job.targets),
    },
    {
      name: 'Waves',
      render: ({ job }: (typeof items)[number]) =>
        `${job.wave_size} agents, ${Math.round(
          job.wave_pause_s / 60,
        )} min pause`,
    },
    {
      name: 'Next run',
      render: ({ job, status }: (typeof items)[number]) =>
        job.enabled
          ? formatDate(masterTime(status.next_run, offset))
          : 'disabled',
    },
    {
      name: 'Last run',
      render: ({ status }: (typeof items)[number]) =>
        status.last_run ? (
          <EuiHealth color={STATE_COLOR[String(status.state)] || 'subdued'}>
            {formatDate(masterTime(status.last_run, offset))} ·{' '}
            {String(status.state)}
          </EuiHealth>
        ) : (
          '—'
        ),
    },
    {
      name: 'Enabled',
      width: '80px',
      render: ({ key, job }: (typeof items)[number]) => (
        <EuiSwitch
          label=''
          showLabel={false}
          checked={job.enabled}
          onChange={() =>
            persist(
              { ...jobs, [key]: { ...job, enabled: !job.enabled } },
              job.enabled ? 'Schedule disabled' : 'Schedule enabled',
            )
          }
        />
      ),
    },
    {
      name: '',
      width: '72px',
      render: ({ key, job }: (typeof items)[number]) => (
        <>
          <EuiButtonIcon
            iconType='pencil'
            aria-label='Edit'
            onClick={() => setEditing({ key, job })}
          />
          <EuiButtonIcon
            iconType='trash'
            color='danger'
            aria-label='Delete'
            onClick={() => setDeleting(key)}
          />
        </>
      ),
    },
  ];

  return (
    <>
      <EuiFlexGroup alignItems='center' responsive={false}>
        <EuiFlexItem>
          <EuiText size='s'>
            Times are in the manager&apos;s time zone
            {scheduler.tz
              ? ` (${scheduler.tz}, UTC${scheduler.utc_offset})`
              : ''}
            . Disconnected agents are skipped and reported in the status.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size='s'
            iconType='play'
            onClick={() => setRunNow(true)}
            data-test-subj='ciscat-run-now'
          >
            Run now
          </EuiButton>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButton
            size='s'
            fill
            iconType='plusInCircle'
            onClick={() => setEditing({ key: newJobKey() })}
            data-test-subj='ciscat-new-schedule'
          >
            New schedule
          </EuiButton>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      <EuiBasicTable
        items={items}
        itemId='key'
        columns={columns}
        noItemsMessage='No schedule yet: CIS-CAT runs only on demand.'
        data-test-subj='ciscat-schedules'
      />
      {editing && (
        <JobFlyout
          initial={editing.job}
          osKeys={osKeys}
          onClose={() => setEditing(undefined)}
          onSave={async job => {
            const stamped = {
              ...job,
              created_by: editing.job?.created_by || user,
              created_at: editing.job?.created_at || new Date().toISOString(),
            };
            if (
              await persist(
                { ...jobs, [editing.key]: stamped },
                'Schedule saved',
              )
            ) {
              setEditing(undefined);
            }
          }}
        />
      )}
      {runNow && (
        <JobFlyout
          runNow
          osKeys={osKeys}
          onClose={() => setRunNow(false)}
          onSave={async job => {
            try {
              await addRequest(
                newRequestKey(),
                {
                  action: 'run',
                  targets: job.targets,
                  wave_size: job.wave_size,
                  wave_pause_s: job.wave_pause_s,
                  label: job.label || 'Run now',
                  requested_by: user,
                  requested_at: new Date().toISOString(),
                },
                (data.status.requests?.processed as string[]) || [],
              );
              getToasts().addSuccess({
                title: 'Run requested',
                text: 'The manager starts it within 5 minutes.',
              });
              setRunNow(false);
              onSaved();
            } catch (e) {
              getToasts().addDanger({
                title: 'Run not requested',
                text: (e as Error).message,
              });
            }
          }}
        />
      )}
      {deleting && (
        <EuiConfirmModal
          title='Delete this schedule?'
          onCancel={() => setDeleting(undefined)}
          onConfirm={async () => {
            const next = { ...jobs };
            delete next[deleting];
            await persist(next, 'Schedule deleted');
            setDeleting(undefined);
          }}
          cancelButtonText='Cancel'
          confirmButtonText='Delete'
          buttonColor='danger'
        >
          <p>{describeJob(jobs[deleting])}</p>
        </EuiConfirmModal>
      )}
    </>
  );
};
