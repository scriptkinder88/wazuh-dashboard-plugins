/*
 * CIS-CAT bridge status as the manager reports it in ciscat-status: scheduler
 * heartbeat, the last apply (per OS: agents, exclusion combinations, checks)
 * and the recent runs.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
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
  SCHEDULER_STALE_MINUTES,
  masterTime,
  pendingRequests,
  recentRuns,
  schedulerHealth,
} from './lib/status';
import { STATE_COLOR as RUN_COLOR, formatDate } from './lib/schedule';
import type { CiscatData } from './ciscat-management';
import { messages } from './messages';

const HEALTH = {
  ok: { color: 'success', text: messages.running },
  stale: {
    color: 'danger',
    text: () => messages.notRunning(SCHEDULER_STALE_MINUTES),
  },
  unknown: { color: 'subdued', text: messages.neverRan },
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
              <h3>{messages.scheduler()}</h3>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiDescriptionList
              compressed
              type='column'
              listItems={[
                {
                  title: messages.state(),
                  description: (
                    <EuiHealth color={HEALTH[health.state].color}>
                      {HEALTH[health.state].text()}
                    </EuiHealth>
                  ),
                },
                {
                  title: messages.lastTick(),
                  description: formatDate(health.lastTick),
                },
                {
                  title: messages.benchmarksPublished(),
                  description: formatDate(
                    masterTime(scheduler.last_sync, offset),
                  ),
                },
                {
                  title: messages.managerTimeZone(),
                  description: scheduler.tz
                    ? `${scheduler.tz} (UTC${scheduler.utc_offset})`
                    : '—',
                },
                {
                  title: messages.pendingRequests(),
                  description: pending.length
                    ? messages.pendingCount(pending.length)
                    : messages.none(),
                },
              ]}
            />
          </EuiPanel>
        </EuiFlexItem>
        <EuiFlexItem>
          <EuiPanel hasBorder paddingSize='m'>
            <EuiTitle size='xs'>
              <h3>{messages.lastApply()}</h3>
            </EuiTitle>
            <EuiSpacer size='s' />
            <EuiDescriptionList
              compressed
              type='column'
              listItems={[
                {
                  title: messages.result(),
                  description: apply.state ? (
                    <EuiHealth
                      color={RUN_COLOR[String(apply.state)] || 'subdued'}
                    >
                      {String(apply.state)}
                    </EuiHealth>
                  ) : (
                    messages.neverApplied()
                  ),
                },
                {
                  title: messages.started(),
                  description: formatDate(masterTime(apply.started_at, offset)),
                },
                {
                  title: messages.finished(),
                  description: formatDate(
                    masterTime(apply.finished_at, offset),
                  ),
                },
                {
                  title: messages.bridgeVersion(),
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
            title={messages.notRunningTitle()}
          >
            <p>{messages.notRunningHelp()}</p>
          </EuiCallOut>
        </>
      )}
      {errors.length > 0 && (
        <>
          <EuiSpacer size='m' />
          <EuiCallOut
            color='warning'
            iconType='alert'
            title={messages.reportedByApply()}
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
        <h3>{messages.policiesPerOs()}</h3>
      </EuiTitle>
      <EuiText size='xs' color='subdued'>
        {messages.combinationsHelp('ciscat-<os>-<combination>')}
      </EuiText>
      <EuiBasicTable
        items={perOs}
        columns={[
          { field: 'osKey', name: messages.columnOs() },
          { field: 'agents', name: messages.columnAgents() },
          { field: 'exclusions', name: messages.columnExclusions() },
          { field: 'combos', name: messages.columnCombinations() },
          {
            field: 'checks',
            name: messages.columnChecks(),
            render: (checks: Record<string, number> = {}) =>
              Object.entries(checks)
                .map(([combo, n]) => `${combo}: ${n}`)
                .join(', ') || '—',
          },
        ]}
        noItemsMessage={messages.noApply()}
      />
      <EuiSpacer size='m' />
      <EuiTitle size='xs'>
        <h3>{messages.recentRuns()}</h3>
      </EuiTitle>
      <EuiBasicTable
        items={runs}
        columns={[
          { field: 'label', name: messages.columnRun() },
          {
            field: 'state',
            name: messages.state(),
            render: (state: string) => (
              <EuiHealth color={RUN_COLOR[state] || 'subdued'}>
                {state}
              </EuiHealth>
            ),
          },
          {
            field: 'lastRun',
            name: messages.started(),
            render: (d?: Date) => formatDate(d),
          },
          {
            field: 'finishedAt',
            name: messages.finished(),
            render: (d?: Date) => formatDate(d),
          },
          { field: 'sent', name: messages.columnAgentsTriggered() },
          { field: 'failed', name: messages.columnFailed() },
          { field: 'skipped', name: messages.columnSkipped() },
        ]}
        noItemsMessage={messages.noRun()}
      />
    </>
  );
};
