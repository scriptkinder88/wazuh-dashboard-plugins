/*
 * CIS-CAT schedules: one-shot, monthly (day N or N days before the end of the
 * month) and weekly runs, in waves, plus "Run now". Job times are the
 * manager's local time; the scheduler publishes its time zone.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import React, { useEffect, useMemo, useState } from 'react';
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
import {
  addRequest,
  fetchGroupNames,
  fetchRunAgents,
  writeList,
} from './lib/lists-api';
import { SCHEDULER_INTERVAL_MINUTES, masterTime } from './lib/status';
import { STATE_COLOR, formatDate, validJobs } from './lib/schedule';
import { JobFlyout, RunAgent } from './job-flyout';
import { messages } from './messages';
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
  const osGroups = Array.from(
    new Set(
      osKeys.map(k => String(data.oskeys[k].group || '')).filter(Boolean),
    ),
  ).sort();
  // agents and groups a run can be sent to, read when a flyout opens
  const [agents, setAgents] = useState<RunAgent[]>([]);
  const [groups, setGroups] = useState<string[]>([]);
  const flyoutOpen = Boolean(editing) || runNow;
  useEffect(() => {
    if (!flyoutOpen) {
      return;
    }
    fetchRunAgents()
      .then(setAgents)
      .catch(() => setAgents([]));
    fetchGroupNames()
      .then(setGroups)
      .catch(() => setGroups([]));
  }, [flyoutOpen]);
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
        title: messages.scheduleNotSaved(),
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
      name: messages.columnSchedule(),
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
      name: messages.columnTargets(),
      render: ({ job }: (typeof items)[number]) => describeTargets(job),
    },
    {
      name: messages.columnWaves(),
      render: ({ job }: (typeof items)[number]) =>
        messages.waves(job.wave_size, Math.round(job.wave_pause_s / 60)),
    },
    {
      name: messages.columnNextRun(),
      render: ({ job, status }: (typeof items)[number]) =>
        job.enabled
          ? formatDate(masterTime(status.next_run, offset))
          : messages.disabled(),
    },
    {
      name: messages.columnLastRun(),
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
      name: messages.columnEnabled(),
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
              job.enabled
                ? messages.scheduleDisabled()
                : messages.scheduleEnabled(),
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
            aria-label={messages.edit()}
            onClick={() => setEditing({ key, job })}
          />
          <WzButtonPermissions
            buttonType='icon'
            permissions={CISCAT_WRITE_PERMISSIONS}
            iconType='trash'
            color='danger'
            aria-label={messages.delete()}
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
            {messages.timeZone(
              scheduler.tz
                ? ` (${scheduler.tz}, UTC${scheduler.utc_offset})`
                : '',
            )}
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
            {messages.runNow()}
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
            {messages.newSchedule()}
          </WzButtonPermissions>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      <EuiBasicTable
        items={items}
        itemId='key'
        columns={columns}
        noItemsMessage={messages.noSchedule()}
        data-test-subj='ciscat-schedules'
      />
      {editing && (
        <JobFlyout
          initial={editing.job}
          osKeys={osKeys}
          osGroups={osGroups}
          groups={groups}
          agents={agents}
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
                messages.scheduleSaved(),
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
          osGroups={osGroups}
          groups={groups}
          agents={agents}
          onClose={() => setRunNow(false)}
          onSave={async job => {
            try {
              await addRequest(
                newRequestKey(),
                {
                  action: 'run',
                  targets: job.targets,
                  agents: job.agents,
                  groups: job.groups,
                  wave_size: job.wave_size,
                  wave_pause_s: job.wave_pause_s,
                  label: job.label || messages.runNow(),
                  requested_by: user,
                  requested_at: new Date().toISOString(),
                },
                (data.status.requests?.processed as string[]) || [],
              );
              getToasts().addSuccess({
                title: messages.runRequested(),
                text: messages.runStartsWithin(SCHEDULER_INTERVAL_MINUTES),
              });
              setRunNow(false);
              onSaved();
            } catch (e) {
              getToasts().addDanger({
                title: messages.runNotRequested(),
                text: (e as Error).message,
              });
            }
          }}
        />
      )}
      {deleting && (
        <EuiConfirmModal
          title={messages.deleteTitle()}
          onCancel={() => setDeleting(undefined)}
          onConfirm={async () => {
            const next = { ...jobs };
            delete next[deleting];
            await persist(next, messages.scheduleDeleted());
            setDeleting(undefined);
          }}
          cancelButtonText={messages.cancel()}
          confirmButtonText={messages.delete()}
          buttonColor='danger'
        >
          <p>{describeJob(jobs[deleting])}</p>
        </EuiConfirmModal>
      )}
    </>
  );
};
