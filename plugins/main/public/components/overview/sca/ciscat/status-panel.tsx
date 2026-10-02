/*
 * CIS-CAT bridge status as the manager reports it in ciscat-status: scheduler
 * heartbeat, the last apply (per OS: agents, exclusion combinations, checks)
 * and the recent runs.
 */
import React from 'react';
import {
  EuiBasicTable,
  EuiCallOut,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHealth,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { validateJob } from '../../../../../common/ciscat/store';
import {
  masterTime,
  pendingRequests,
  recentRuns,
  schedulerHealth,
} from './lib/status';
import type { CiscatData } from './ciscat-management';

const formatDate = (date?: Date) => (date ? date.toLocaleString() : '—');

const HEALTH = {
  ok: { color: 'success', text: 'Running' },
  stale: { color: 'danger', text: 'Not running (no tick for 15 minutes)' },
  unknown: { color: 'subdued', text: 'Never ran' },
};

const RUN_COLOR: Record<string, string> = {
  ok: 'success',
  error: 'danger',
  running: 'primary',
  starting: 'primary',
};

export const StatusPanel = ({ data }: { data: CiscatData }) => {
  const { status } = data;
  const scheduler = status.scheduler || {};
  const apply = status.apply || {};
  const offset = scheduler.utc_offset;
  const health = schedulerHealth(status);
  const labels = Object.entries(data.schedule.records).reduce(
    (acc, [key, rec]) => {
      try {
        acc[key] = validateJob(rec).label || key;
      } catch {
        // ignore invalid jobs
      }
      return acc;
    },
    {} as Record<string, string>,
  );
  const runs = recentRuns(status, labels);
  const pending = pendingRequests(data.requests.records, status);
  const perOs = Object.entries(
    (apply.per_os || {}) as Record<string, Record<string, unknown>>,
  ).map(([osKey, s]) => ({ osKey, ...s }));
  const errors = (apply.errors as string[]) || [];

  return (
    <>
      <EuiFlexGroup>
        <EuiFlexItem>
          <EuiPanel hasBorder paddingSize='m'>
            <EuiTitle size='xs'>
              <h3>Scheduler</h3>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiDescriptionList
              compressed
              type='column'
              listItems={[
                {
                  title: 'State',
                  description: (
                    <EuiHealth color={HEALTH[health.state].color}>
                      {HEALTH[health.state].text}
                    </EuiHealth>
                  ),
                },
                {
                  title: 'Last tick',
                  description: formatDate(health.lastTick),
                },
                {
                  title: 'Benchmarks published',
                  description: formatDate(
                    masterTime(scheduler.last_sync, offset),
                  ),
                },
                {
                  title: 'Manager time zone',
                  description: scheduler.tz
                    ? `${scheduler.tz} (UTC${scheduler.utc_offset})`
                    : '—',
                },
                {
                  title: 'Pending requests',
                  description: pending.length
                    ? `${pending.length} (handled at the next tick)`
                    : 'none',
                },
              ]}
            />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel hasBorder paddingSize='m'>
            <EuiTitle size='xs'>
              <h3>Last apply</h3>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiDescriptionList
              compressed
              type='column'
              listItems={[
                {
                  title: 'Result',
                  description: apply.state ? (
                    <EuiHealth
                      color={RUN_COLOR[String(apply.state)] || 'subdued'}
                    >
                      {String(apply.state)}
                    </EuiHealth>
                  ) : (
                    'never applied from the dashboard'
                  ),
                },
                {
                  title: 'Started',
                  description: formatDate(masterTime(apply.started_at, offset)),
                },
                {
                  title: 'Finished',
                  description: formatDate(
                    masterTime(apply.finished_at, offset),
                  ),
                },
                {
                  title: 'Bridge version',
                  description: String(apply.version || '—'),
                },
              ]}
            />
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>
      {health.state === 'stale' && (
        <>
          <EuiSpacer size='m' />
          <EuiCallOut
            color='danger'
            iconType='alert'
            title='The scheduler is not running'
          >
            <p>
              Check the cron entry /etc/cron.d/ciscat-scheduler and
              /opt/ciscat/log/ciscat-scheduler.log on the manager. Saved changes
              and schedules wait until it runs again.
            </p>
          </EuiCallOut>
        </>
      )}
      {errors.length > 0 && (
        <>
          <EuiSpacer size='m' />
          <EuiCallOut
            color='warning'
            iconType='alert'
            title='Reported by the last apply'
          >
            <ul>
              {errors.map(e => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </EuiCallOut>
        </>
      )}
      <EuiSpacer size='m' />
      <EuiTitle size='xs'>
        <h3>Policies per OS</h3>
      </EuiTitle>
      <EuiText size='xs' color='subdued'>
        Agents with the same agent or group exclusions share a combination
        (group ciscat-&lt;os&gt;-&lt;combination&gt;); &quot;base&quot; has
        none.
      </EuiText>
      <EuiBasicTable
        items={perOs}
        columns={[
          { field: 'osKey', name: 'OS' },
          { field: 'agents', name: 'Agents' },
          { field: 'exclusions', name: 'Exclusions' },
          { field: 'combos', name: 'Combinations' },
          {
            field: 'checks',
            name: 'Checks per combination',
            render: (checks: Record<string, number> = {}) =>
              Object.entries(checks)
                .map(([combo, n]) => `${combo}: ${n}`)
                .join(', ') || '—',
          },
        ]}
        noItemsMessage='No apply yet'
      />
      <EuiSpacer size='m' />
      <EuiTitle size='xs'>
        <h3>Recent runs</h3>
      </EuiTitle>
      <EuiBasicTable
        items={runs}
        columns={[
          { field: 'label', name: 'Run' },
          {
            field: 'state',
            name: 'State',
            render: (state: string) => (
              <EuiHealth color={RUN_COLOR[state] || 'subdued'}>
                {state}
              </EuiHealth>
            ),
          },
          {
            field: 'lastRun',
            name: 'Started',
            render: (d?: Date) => formatDate(d),
          },
          {
            field: 'finishedAt',
            name: 'Finished',
            render: (d?: Date) => formatDate(d),
          },
          { field: 'sent', name: 'Agents triggered' },
          { field: 'failed', name: 'Failed' },
          { field: 'skipped', name: 'Skipped (disconnected)' },
        ]}
        noItemsMessage='No run yet'
      />
    </>
  );
};
