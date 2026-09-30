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

export interface CiscatData {
  oskeys: ListRecords;
  status: ListRecords;
  exclusions: LoadedList;
  schedule: LoadedList;
  requests: LoadedList;
}

type TabId = 'exclusions' | 'schedule' | 'status';

const TABS: Array<{ id: TabId; name: string }> = [
  { id: 'exclusions', name: 'Exclusions' },
  { id: 'schedule', name: 'Schedule' },
  { id: 'status', name: 'Status' },
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
      const [oskeys, status, exclusions, schedule, requests] =
        await Promise.all([
          readList(CISCAT_LISTS.oskeys, existing),
          readList(CISCAT_LISTS.status, existing),
          readList(CISCAT_LISTS.exclusions, existing),
          readList(CISCAT_LISTS.schedule, existing),
          readList(CISCAT_LISTS.requests, existing),
        ]);
      setData({
        oskeys: oskeys.records,
        status: status.records,
        exclusions,
        schedule,
        requests,
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
            <h2>CIS-CAT Pro</h2>
          </EuiTitle>
          <EuiText size='xs' color='subdued'>
            Exclusions and schedules for the CIS-CAT assessments run by the
            manager. Changes are stored on the manager and applied by its
            scheduler.
          </EuiText>
        </EuiFlexItem>
        <EuiFlexItem grow={false}>
          <EuiButtonEmpty
            iconType='refresh'
            onClick={load}
            isLoading={loading}
            data-test-subj='ciscat-reload'
          >
            Reload
          </EuiButtonEmpty>
        </EuiFlexItem>
      </EuiFlexGroup>
      <EuiSpacer size='s' />
      <EuiTabs size='s'>
        {TABS.map(t => (
          <EuiTab
            key={t.id}
            isSelected={tab === t.id}
            onClick={() => setTab(t.id)}
            data-test-subj={`ciscat-tab-${t.id}`}
          >
            {t.name}
          </EuiTab>
        ))}
      </EuiTabs>
      <EuiSpacer size='m' />
      {error && (
        <EuiCallOut
          color='danger'
          iconType='alert'
          title='Cannot read the CIS-CAT data'
        >
          <p>{error}</p>
        </EuiCallOut>
      )}
      {!data && loading && <EuiLoadingSpinner size='l' />}
      {noBridge && (
        <EuiCallOut
          color='warning'
          iconType='iInCircle'
          title='The CIS-CAT bridge has not published any data yet'
        >
          <p>
            Install the bridge on the manager and let its scheduler run once
            (every 5 minutes): it publishes the benchmarks and the OS list shown
            here.
          </p>
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
