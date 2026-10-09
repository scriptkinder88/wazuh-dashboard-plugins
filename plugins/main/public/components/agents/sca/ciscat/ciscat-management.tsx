/*
 * CIS-CAT tab of Configuration Assessment: exclusions (tailoring), schedules
 * and status of the CIS-CAT Pro bridge on the manager. Everything is read and
 * written as Wazuh lists through the Wazuh API (tools/ciscat-bridge/CONTRACT.md).
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  EuiButtonEmpty,
  EuiCallOut,
  EuiFlexGroup,
  EuiFlexItem,
  EuiLoadingSpinner,
  EuiPanel,
  EuiSpacer,
  EuiTab,
  EuiTabs,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { CISCAT_LISTS, ListRecords } from '../../../../../common/ciscat/store';
import {
  LoadedList,
  existingLists,
  fetchCurrentUserName,
  readList,
} from './lib/lists-api';
import { ExclusionsPanel } from './exclusions-panel';
import { SchedulePanel } from './schedule-panel';
import { StatusPanel } from './status-panel';
import { CoveragePanel } from './coverage-panel';
import { messages } from './messages';
import { SCHEDULER_INTERVAL_MINUTES } from './lib/status';

export interface CiscatData {
  oskeys: ListRecords;
  status: ListRecords;
  exclusions: LoadedList;
  schedule: LoadedList;
  requests: LoadedList;
  targets: LoadedList;
  history: ListRecords;
}

type TabId = 'exclusions' | 'schedule' | 'status';

const TABS: Array<{ id: TabId; name: () => string }> = [
  { id: 'exclusions', name: messages.tabExclusions },
  { id: 'schedule', name: messages.tabSchedule },
  { id: 'status', name: messages.tabStatus },
];

export const CiscatManagement = () => {
  const [tab, setTab] = useState<TabId>('exclusions');
  const [data, setData] = useState<CiscatData>();
  const [user, setUser] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const existing = await existingLists();
      const [oskeys, status, exclusions, schedule, requests, targets, history] =
        await Promise.all([
          readList(CISCAT_LISTS.oskeys, existing),
          readList(CISCAT_LISTS.status, existing),
          readList(CISCAT_LISTS.exclusions, existing),
          readList(CISCAT_LISTS.schedule, existing),
          readList(CISCAT_LISTS.requests, existing),
          readList(CISCAT_LISTS.targets, existing),
          readList(CISCAT_LISTS.history, existing),
        ]);
      setData({
        oskeys: oskeys.records,
        status: status.records,
        exclusions,
        schedule,
        requests,
        targets,
        history: history.records,
      });
    } catch (e) {
      setError((e as Error).message || String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    fetchCurrentUserName().then(setUser);
  }, [load]);

  const noBridge =
    data && !Object.keys(data.oskeys).length && !data.exclusions.exists;

  return (
    <EuiPanel paddingSize='m' data-test-subj='ciscat-management'>
      <EuiFlexGroup alignItems='center' gutterSize='s' responsive={false}>
        <EuiFlexItem>
          <EuiTitle size='s'>
            <h2>{messages.title()}</h2>
          </EuiTitle>
          <EuiText size='xs' color='subdued'>
            {messages.description()}
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty
            iconType='refresh'
            onClick={load}
            isLoading={loading}
            data-test-subj='ciscat-reload'
          >
            {messages.reload()}
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='m' />
      {data && !noBridge && (
        <>
          <CoveragePanel data={data} />
          <EuiSpacer size='m' />
        </>
      )}
      <EuiTabs size='s'>
        {TABS.map(t => (
          <EuiTab
            key={t.id}
            isSelected={tab === t.id}
            onClick={() => setTab(t.id)}
            data-test-subj={`ciscat-tab-${t.id}`}
          >
            {t.name()}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size='m' />
      {error && (
        <EuiCallOut
          color='danger'
          iconType='alert'
          title={messages.cannotRead()}
        >
          <p>{error}</p>
        </EuiCallOut>
      )}
      {!data && loading && <EuiLoadingSpinner size='l' />}
      {noBridge && (
        <EuiCallOut
          color='warning'
          iconType='iInCircle'
          title={messages.noBridgeTitle()}
        >
          <p>{messages.noBridge(SCHEDULER_INTERVAL_MINUTES)}</p>
        </EuiCallOut>
      )}
      {data && tab === 'exclusions' && (
        <ExclusionsPanel data={data} user={user} onSaved={load} />
      )}
      {data && tab === 'schedule' && (
        <SchedulePanel data={data} user={user} onSaved={load} />
      )}
      {data && tab === 'status' && <StatusPanel data={data} />}
    </EuiPanel>
  );
};
