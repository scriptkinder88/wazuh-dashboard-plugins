import React, { useEffect, useMemo, useState } from 'react';
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

const AGENTS_PAGE_SIZE = 500;

type ScaReportAgentSelectorProps = {
  initialAgentId?: string;
  onCancel: () => void;
  onGenerate: (agentIds: string[]) => Promise<void> | void;
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
              wait_for_complete: true,
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
          setLoadError(error?.message || 'Unable to load servers.');
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

  const generateReport = async () => {
    if (!selectedAgentIds.length || generating) {
      return;
    }

    try {
      setGenerating(true);
      await onGenerate(selectedAgentIds);
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
          aria-label={`Select ${agent.name || agent.id}`}
        />
      ),
    },
    {
      field: 'id',
      name: 'ID',
      width: '80px',
    },
    {
      field: 'name',
      name: 'Server',
    },
    {
      name: 'Operating system',
      render: agent =>
        [agent?.os?.name, agent?.os?.version].filter(Boolean).join(' ') || '-',
    },
    {
      field: 'status',
      name: 'Status',
      width: '120px',
    },
  ];

  return (
    <EuiModal onClose={onCancel} maxWidth={900}>
      <EuiModalHeader>
        <EuiModalHeaderTitle>Select servers for the SCA report</EuiModalHeaderTitle>
      </EuiModalHeader>

      <EuiModalBody>
        <EuiText size='s'>
          Select all servers to include in one PDF. Wazuh 5 will render the SCA
          overview dashboard using the complete selected server list as a
          single filter.
        </EuiText>

        <EuiSpacer size='m' />

        <EuiFieldSearch
          placeholder='Filter by ID, server name, operating system or status'
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
              Select all filtered ({filteredAgents.length})
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty
              color='danger'
              onClick={() => setSelectedAgentIds([])}
              isDisabled={!selectedAgentIds.length}
            >
              Clear selection
            </EuiButtonEmpty>
          </EuiFlexItem>
          <EuiFlexItem>
            <EuiText textAlign='right' size='s'>
              <strong>{selectedAgentIds.length}</strong> server
              {selectedAgentIds.length === 1 ? '' : 's'} selected
            </EuiText>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiSpacer size='s' />

        {loadError ? (
          <EuiCallOut title='Unable to load servers' color='danger'>
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
        <EuiButtonEmpty onClick={onCancel}>Cancel</EuiButtonEmpty>
        <EuiButton
          fill
          iconType='document'
          onClick={generateReport}
          isLoading={generating}
          isDisabled={
            loadingAgents || Boolean(loadError) || !selectedAgentIds.length
          }
        >
          Generate report ({selectedAgentIds.length})
        </EuiButton>
      </EuiModalFooter>
    </EuiModal>
  );
};
