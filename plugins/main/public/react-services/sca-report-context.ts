import {
  FILTER_OPERATOR,
  PatternDataSourceFilterManager,
} from '../components/common/data-source/pattern/pattern-data-source-filter-manager';

export const SCA_REPORT_AGENT_FIELD = 'wazuh.agent.id';
export const SCA_REPORT_FILTER_CONTROLLED_BY = 'sca-report-selected-agents';

export const normalizeScaReportAgentIds = (
  agentIds: string[] | string | undefined,
): string[] => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

export const buildScaMultiServerReportContext = (
  context: any,
  agentIds: string[] | string,
) => {
  const normalizedAgentIds = normalizeScaReportAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    throw new Error('Select at least one server for the SCA report.');
  }

  const indexPatternId = context?.indexPattern?.id;
  if (!indexPatternId) {
    throw new Error('The SCA index pattern is not available for reporting.');
  }

  if (!context?.overviewDashboardSavedObjectId) {
    throw new Error(
      'The SCA overview dashboard is not available for reporting.',
    );
  }

  const filters = (context?.filters || []).filter(
    filter =>
      filter?.meta?.key !== SCA_REPORT_AGENT_FIELD &&
      filter?.meta?.controlledBy !== SCA_REPORT_FILTER_CONTROLLED_BY,
  );

  const selectedAgentsFilter = PatternDataSourceFilterManager.createFilter(
    FILTER_OPERATOR.IS_ONE_OF,
    SCA_REPORT_AGENT_FIELD,
    normalizedAgentIds,
    indexPatternId,
    SCA_REPORT_FILTER_CONTROLLED_BY,
  );

  selectedAgentsFilter.meta.alias = `Selected servers (${
    normalizedAgentIds.length
  })`;

  return {
    ...context,
    dashboardSavedObjectId: context.overviewDashboardSavedObjectId,
    filters: [...filters, selectedAgentsFilter],
    selectedScaAgentIds: normalizedAgentIds,
  };
};
