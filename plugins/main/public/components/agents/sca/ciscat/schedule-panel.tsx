/*
 * CIS-CAT schedules: one-shot, monthly (day N or N days before the end of the
 * month) and weekly runs, in waves, plus "Run now". Job times are the
 * manager's local time; the scheduler publishes its time zone.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useMemo, useState } from 'react';
import {
  EuiBasicTable,
  EuiConfirmModal,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { WzButtonPermissions } from '../../../common/permissions/button';
import { CISCAT_WRITE_PERMISSIONS } from './lib/permissions';
import {
  CISCAT_LISTS,
  Job,
  newJobKey,
  newRequestKey,
} from '../../../../../common/ciscat/store';
import { getToasts } from '../../../../kibana-services';
import { describeJob, describeTargets } from './lib/composer';
import { addRequest, writeList } from './lib/lists-api';
import { masterTime } from './lib/status';
import { STATE_COLOR, formatDate, validJobs } from './lib/schedule';
import { JobFlyout } from './job-flyout';
import type { CiscatData } from './ciscat-management';

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
        <WzButtonPermissions
          buttonType='switch'
          permissions={CISCAT_WRITE_PERMISSIONS}
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
          <WzButtonPermissions
            buttonType='icon'
            permissions={CISCAT_WRITE_PERMISSIONS}
            iconType='pencil'
            aria-label='Edit'
            onClick={() => setEditing({ key, job })}
          />
          <WzButtonPermissions
            buttonType='icon'
            permissions={CISCAT_WRITE_PERMISSIONS}
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
          <WzButtonPermissions
            permissions={CISCAT_WRITE_PERMISSIONS}
            size='s'
            iconType='play'
            onClick={() => setRunNow(true)}
            data-test-subj='ciscat-run-now'
          >
            Run now
          </WzButtonPermissions>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <WzButtonPermissions
            permissions={CISCAT_WRITE_PERMISSIONS}
            size='s'
            fill
            iconType='plusInCircle'
            onClick={() => setEditing({ key: newJobKey() })}
            data-test-subj='ciscat-new-schedule'
          >
            New schedule
          </WzButtonPermissions>
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
