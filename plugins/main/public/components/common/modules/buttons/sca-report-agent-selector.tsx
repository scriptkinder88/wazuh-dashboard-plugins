import React, { useEffect, useMemo, useState } from 'react';
import { i18n } from '@osd/i18n';
import {
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
  EuiFieldSearch,
  EuiFlexGroup,
  EuiFlexItem,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
  EuiText,
} from '@elastic/eui';
import { WzRequest } from '../../../../react-services';
import { SCA_REPORT_MAX_AGENTS } from '../../../../../common/sca/report-limits';

const AGENTS_PAGE_SIZE = 100;

export type ScaReportOptions = {
  /** Include the per-server tables with every control. */
  details: boolean;
};

type ScaReportAgentSelectorProps = {
  initialAgentId?: string;
  onCancel: () => void;
  onGenerate: (
    agentIds: string[],
    options: ScaReportOptions,
  ) => Promise<void> | void;
};

const selectedText = (count: number) => {
  if (count === 1) {
    return i18n.translate('wazuh.scaReport.selector.selectedOne', {
      defaultMessage: 'server selected',
    });
  }
  return i18n.translate('wazuh.scaReport.selector.selectedMany', {
    defaultMessage: 'servers selected',
  });
};

export const ScaReportAgentSelector = ({
  initialAgentId,
  onCancel,
  onGenerate,
}: ScaReportAgentSelectorProps) => {
  const [agents, setAgents] = useState<any[]>([]);
  const [selectedAgentIds, setSelectedAgentIds] = useState<string[]>(
    initialAgentId ? [String(initialAgentId)] : [],
  );
  const [search, setSearch] = useState('');
  const [loadingAgents, setLoadingAgents] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [includeDetails, setIncludeDetails] = useState(false);

  useEffect(() => {
    let active = true;

    const loadAgents = async () => {
      try {
        setLoadingAgents(true);
        const loadedAgents: any[] = [];
        let totalAgents: number | null = null;

        do {
          const response = await WzRequest.apiReq('GET', '/agents', {
            params: {
              q: 'id!=000',
              offset: loadedAgents.length,
              limit: AGENTS_PAGE_SIZE,
              sort: '+name',
              select: 'id,name,status,os.name,os.version',
            },
          });

          const data = response?.data?.data || {};
          const page = data.affected_items || [];

          loadedAgents.push(...page);
          totalAgents =
            typeof data.total_affected_items === 'number'
              ? data.total_affected_items
              : loadedAgents.length;

          if (!page.length) {
            break;
          }
        } while (loadedAgents.length < totalAgents);

        if (active) {
          setAgents(loadedAgents);
          setLoadError('');
        }
      } catch (error) {
        if (active) {
          setLoadError(
            error?.message ||
              i18n.translate('wazuh.scaReport.selector.loadError', {
                defaultMessage: 'Unable to load agents.',
              }),
          );
        }
      } finally {
        if (active) {
          setLoadingAgents(false);
        }
      }
    };

    loadAgents();

    return () => {
      active = false;
    };
  }, []);

  const filteredAgents = useMemo(() => {
    const term = search.trim().toLowerCase();

    if (!term) {
      return agents;
    }

    return agents.filter(agent => {
      const os = [agent?.os?.name, agent?.os?.version]
        .filter(Boolean)
        .join(' ');

      return [agent?.id, agent?.name, agent?.status, os]
        .filter(Boolean)
        .some(value => String(value).toLowerCase().includes(term));
    });
  }, [agents, search]);

  const pageAgents = useMemo(() => {
    const start = pageIndex * pageSize;
    return filteredAgents.slice(start, start + pageSize);
  }, [filteredAgents, pageIndex, pageSize]);

  const selectedAgentIdSet = useMemo(
    () => new Set(selectedAgentIds),
    [selectedAgentIds],
  );

  const toggleAgent = (agentId: string) => {
    setSelectedAgentIds(current =>
      current.includes(agentId)
        ? current.filter(id => id !== agentId)
        : [...current, agentId],
    );
  };

  const selectFilteredAgents = () => {
    setSelectedAgentIds(current => [
      ...new Set([
        ...current,
        ...filteredAgents.map(agent => String(agent.id)),
      ]),
    ]);
  };

  const tooManyAgents = selectedAgentIds.length > SCA_REPORT_MAX_AGENTS;
  const generateReport = async () => {
    if (!selectedAgentIds.length || tooManyAgents || generating) {
      return;
    }

    try {
      setGenerating(true);
      await onGenerate(selectedAgentIds, { details: includeDetails });
    } finally {
      setGenerating(false);
    }
  };

  const columns: any[] = [
    {
      name: '',
      width: '42px',
      render: agent => (
        <EuiCheckbox
          id={`sca-report-agent-${agent.id}`}
          checked={selectedAgentIdSet.has(String(agent.id))}
          onChange={() => toggleAgent(String(agent.id))}
          aria-label={i18n.translate('wazuh.scaReport.selector.selectAgent', {
            defaultMessage: 'Select {agent}',
            values: { agent: agent.name || agent.id },
          })}
        />
      ),
    },
    {
      field: 'id',
      name: i18n.translate('wazuh.scaReport.selector.id', {
        defaultMessage: 'ID',
      }),
      width: '80px',
    },
    {
      field: 'name',
      name: i18n.translate('wazuh.scaReport.selector.server', {
        defaultMessage: 'Server',
      }),
    },
    {
      name: i18n.translate('wazuh.scaReport.selector.os', {
        defaultMessage: 'Operating system',
      }),
      render: agent =>
        [agent?.os?.name, agent?.os?.version].filter(Boolean).join(' ') || '-',
    },
    {
      field: 'status',
      name: i18n.translate('wazuh.scaReport.selector.status', {
        defaultMessage: 'Status',
      }),
      width: '120px',
    },
  ];

  return (
    <EuiModal onClose={onCancel} maxWidth={900}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>
          {i18n.translate('wazuh.scaReport.selector.title', {
            defaultMessage: 'Select servers for the SCA report',
          })}
        </EuiModalHeaderTitle>
      </EuiModalHeader>

      <EuiModalBody>
        <EuiText size='s'>
          {i18n.translate('wazuh.scaReport.selector.description', {
            defaultMessage:
              'Select all servers that must be included in this PDF. Each selected ' +
              'server will get its own SCA policy summary and complete control list.',
          })}
        </EuiText>

        <EuiSpacer size='m' />

        <EuiFieldSearch
          placeholder={i18n.translate('wazuh.scaReport.selector.search', {
            defaultMessage:
              'Filter by ID, server name, operating system or status',
          })}
          value={search}
          onChange={event => {
            setSearch(event.target.value);
            setPageIndex(0);
          }}
          isClearable
          fullWidth
        />

        <EuiSpacer size='s' />

        <EuiFlexGroup alignItems='center' responsive={false}>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              onClick={selectFilteredAgents}
              isDisabled={!filteredAgents.length}
            >
              {i18n.translate('wazuh.scaReport.selector.selectFiltered', {
                defaultMessage: 'Select all filtered ({count})',
                values: { count: filteredAgents.length },
              })}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              color='danger'
              onClick={() => setSelectedAgentIds([])}
              isDisabled={!selectedAgentIds.length}
            >
              {i18n.translate('wazuh.scaReport.selector.clear', {
                defaultMessage: 'Clear selection',
              })}
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiText textAlign='right' size='s'>
              <strong>{selectedAgentIds.length}</strong>{' '}
              {selectedText(selectedAgentIds.length)}
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size='s' />

        {tooManyAgents && (
          <>
            <EuiCallOut
              title={i18n.translate('wazuh.scaReport.selector.tooManyTitle', {
                defaultMessage: 'Select at most {max} servers',
                values: { max: SCA_REPORT_MAX_AGENTS },
              })}
              color='warning'
              iconType='alert'
              data-test-subj='sca-report-too-many-agents'
            >
              <p>
                {i18n.translate('wazuh.scaReport.selector.tooMany', {
                  defaultMessage:
                    'A report includes up to {max} servers. Narrow the selection or ' +
                    'generate several reports.',
                  values: { max: SCA_REPORT_MAX_AGENTS },
                })}
              </p>
            </EuiCallOut>
            <EuiSpacer size='s' />
          </>
        )}

        {loadError ? (
          <EuiCallOut
            title={i18n.translate('wazuh.scaReport.selector.cannotLoad', {
              defaultMessage: 'Unable to load servers',
            })}
            color='danger'
          >
            <p>{loadError}</p>
          </EuiCallOut>
        ) : (
          <EuiBasicTable
            items={pageAgents}
            columns={columns}
            loading={loadingAgents}
            itemId='id'
            pagination={{
              pageIndex,
              pageSize,
              totalItemCount: filteredAgents.length,
              pageSizeOptions: [10, 25, 50, 100],
            }}
            onChange={({ page = {} }) => {
              setPageIndex(page.index ?? 0);
              setPageSize(page.size ?? pageSize);
            }}
          />
        )}
      </EuiModalBody>

      <EuiModalFooter>
        <EuiCheckbox
          id='sca-report-include-details'
          data-test-subj='sca-report-include-details'
          label={i18n.translate('wazuh.scaReport.selector.details', {
            defaultMessage:
              'Include detailed results by server (every control, larger report)',
          })}
          checked={includeDetails}
          onChange={event => setIncludeDetails(event.target.checked)}
        />
        <EuiButtonEmpty onClick={onCancel}>
          {i18n.translate('wazuh.scaReport.selector.cancel', {
            defaultMessage: 'Cancel',
          })}
        </EuiButtonEmpty>
        <EuiButton
          fill
          iconType='document'
          onClick={generateReport}
          isLoading={generating}
          isDisabled={
            loadingAgents ||
            Boolean(loadError) ||
            !selectedAgentIds.length ||
            tooManyAgents
          }
          data-test-subj='sca-report-generate'
        >
          {i18n.translate('wazuh.scaReport.selector.generate', {
            defaultMessage: 'Generate report ({count})',
            values: { count: selectedAgentIds.length },
          })}
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
