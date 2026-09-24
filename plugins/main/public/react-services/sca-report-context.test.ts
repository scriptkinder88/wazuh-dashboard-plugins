import {
  buildScaMultiServerReportContext,
  normalizeScaReportAgentIds,
  SCA_REPORT_AGENT_FIELD,
  SCA_REPORT_FILTER_CONTROLLED_BY,
} from './sca-report-context';

describe('SCA multi-server reporting context', () => {
  it('deduplicates selected server IDs while preserving selection order', () => {
    expect(normalizeScaReportAgentIds(['003', '004', '003'])).toEqual([
      '003',
      '004',
    ]);
  });

  it('switches to the overview dashboard and replaces any pinned-agent filter', () => {
    const context = {
      dashboardSavedObjectId: 'sca-agent-dashboard',
      overviewDashboardSavedObjectId: 'sca-overview-dashboard',
      indexPattern: { id: 'wazuh-states-sca' },
      filters: [
        {
          meta: {
            key: SCA_REPORT_AGENT_FIELD,
            controlledBy: 'pinned-agent',
          },
          query: {
            match_phrase: {
              [SCA_REPORT_AGENT_FIELD]: { query: '003' },
            },
          },
        },
        {
          meta: {
            key: 'wazuh.cluster.name',
            controlledBy: 'cluster',
          },
        },
      ],
    };

    const result = buildScaMultiServerReportContext(context, [
      '003',
      '004',
      '003',
    ]);

    expect(result.dashboardSavedObjectId).toBe('sca-overview-dashboard');
    expect(result.selectedScaAgentIds).toEqual(['003', '004']);
    expect(result.filters).toHaveLength(2);
    expect(result.filters[0].meta.key).toBe('wazuh.cluster.name');

    const selectedAgentsFilter = result.filters[1];
    expect(selectedAgentsFilter.meta).toEqual(
      expect.objectContaining({
        key: SCA_REPORT_AGENT_FIELD,
        params: ['003', '004'],
        controlledBy: SCA_REPORT_FILTER_CONTROLLED_BY,
        alias: 'Selected servers (2)',
      }),
    );
    expect(selectedAgentsFilter.query.bool.should).toHaveLength(2);
  });

  it('requires at least one selected server', () => {
    expect(() =>
      buildScaMultiServerReportContext(
        {
          overviewDashboardSavedObjectId: 'sca-overview-dashboard',
          indexPattern: { id: 'wazuh-states-sca' },
        },
        [],
      ),
    ).toThrow('Select at least one server');
  });
});
