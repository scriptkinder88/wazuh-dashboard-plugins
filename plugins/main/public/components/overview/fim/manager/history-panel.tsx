/*
 * Versions of agent.conf saved before each change (the last few per group),
 * which can be viewed and restored.
 */
import React, { useState } from 'react';
import {
  EuiButtonEmpty,
  EuiCodeBlock,
  EuiFieldSearch,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiInMemoryTable,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { HISTORY_DEPTH, HistoryEntry } from './lib/fim-api';

export const HistoryPanel = ({
  entries,
  onRestore,
}: {
  entries: HistoryEntry[];
  onRestore: (entry: HistoryEntry) => void;
}) => {
  const [search, setSearch] = useState('');
  const [viewed, setViewed] = useState<HistoryEntry>();
  const q = search.trim().toLowerCase();
  const shown = entries.filter(
    e => !q || [e.group, e.by, e.note].join(' ').toLowerCase().includes(q),
  );
  return (
    <>
      <EuiText size='s' color='subdued'>
        <p>
          The version of agent.conf each group had before a change made here
          (last {HISTORY_DEPTH} per group). Restoring shows the changes first.
        </p>
      </EuiText>
      <EuiSpacer size='s' />
      <EuiFieldSearch
        fullWidth
        placeholder='Group, user, note…'
        value={search}
        onChange={e => setSearch(e.target.value)}
      />
      <EuiSpacer size='m' />
      <EuiInMemoryTable
        items={shown}
        itemId='key'
        pagination={true}
        data-test-subj='fim-history-table'
        columns={[
          {
            name: 'Saved',
            width: '160px',
            render: (e: HistoryEntry) => e.at.slice(0, 19).replace('T', ' '),
          },
          { name: 'Group', render: (e: HistoryEntry) => e.group },
          {
            name: 'Changed by',
            render: (e: HistoryEntry) => e.by || 'unknown',
          },
          { name: 'Change', render: (e: HistoryEntry) => e.note },
          {
            name: '',
            width: '190px',
            render: (e: HistoryEntry) => (
              <div>
                <EuiButtonEmpty size='xs' onClick={() => setViewed(e)}>
                  View
                </EuiButtonEmpty>
                <EuiButtonEmpty
                  size='xs'
                  iconType='editorUndo'
                  onClick={() => onRestore(e)}
                  data-test-subj='fim-history-restore'
                >
                  Restore
                </EuiButtonEmpty>
              </div>
            ),
          },
        ]}
        message='No saved versions yet'
      />
      {viewed && (
        <EuiFlyout onClose={() => setViewed(undefined)} size='m' ownFocus>
          <EuiFlyoutHeader hasBorder>
            <EuiTitle size='s'>
              <h3>
                {viewed.group} — {viewed.at.slice(0, 19).replace('T', ' ')}
              </h3>
            </EuiTitle>
          </EuiFlyoutHeader>
          <EuiFlyoutBody>
            <EuiCodeBlock language='xml' fontSize='s' isCopyable>
              {viewed.content}
            </EuiCodeBlock>
          </EuiFlyoutBody>
        </EuiFlyout>
      )}
    </>
  );
};
