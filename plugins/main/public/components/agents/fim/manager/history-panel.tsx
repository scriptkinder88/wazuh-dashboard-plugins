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
import { WzButtonPermissions } from '../../../common/permissions/button';
import { FIM_WRITE_PERMISSIONS } from './lib/permissions';
import { messages } from './messages';

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
        <p>{messages.historyDescription(HISTORY_DEPTH)}</p>
      </EuiText>
      <EuiSpacer size='s' />
      <EuiFieldSearch
        fullWidth
        placeholder={messages.historySearch()}
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
            name: messages.columnSaved(),
            width: '160px',
            render: (e: HistoryEntry) => e.at.slice(0, 19).replace('T', ' '),
          },
          {
            name: messages.columnGroup(),
            render: (e: HistoryEntry) => e.group,
          },
          {
            name: messages.columnChangedBy(),
            render: (e: HistoryEntry) => e.by || messages.unknownUser(),
          },
          {
            name: messages.columnChange(),
            render: (e: HistoryEntry) => e.note,
          },
          {
            name: '',
            width: '190px',
            render: (e: HistoryEntry) => (
              <div>
                <EuiButtonEmpty size='xs' onClick={() => setViewed(e)}>
                  {messages.view()}
                </EuiButtonEmpty>
                <WzButtonPermissions
                  buttonType='empty'
                  permissions={FIM_WRITE_PERMISSIONS}
                  size='xs'
                  iconType='editorUndo'
                  onClick={() => onRestore(e)}
                  data-test-subj='fim-history-restore'
                >
                  {messages.restore()}
                </WzButtonPermissions>
              </div>
            ),
          },
        ]}
        message={messages.noHistory()}
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
