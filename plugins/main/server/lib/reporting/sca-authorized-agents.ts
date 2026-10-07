/*
 * Agents of an SCA report restricted to those the current user can read with
 * the Wazuh server API. The report reads the indexer, where the agent
 * permissions of the Wazuh RBAC do not apply, so the agent IDs sent by the
 * browser are checked here before any data is collected.
 */
import { SCA_REPORT_MAX_AGENTS } from '../../../common/sca/report-limits';

export class ScaReportAgentsError extends Error {}

const normalize = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

/**
 * The requested agent IDs the current user can read, in the requested order.
 * Agents the API does not return are dropped; an error is thrown when none
 * remain or when more than SCA_REPORT_MAX_AGENTS are requested.
 */
export async function filterAuthorizedAgentIds(
  context,
  agentIds: string | string[],
  apiId: string,
): Promise<string[]> {
  const requested = normalize(agentIds);
  if (!requested.length) {
    throw new ScaReportAgentsError('No agent selected for the SCA report');
  }
  if (requested.length > SCA_REPORT_MAX_AGENTS) {
    throw new ScaReportAgentsError(
      `An SCA report can include at most ${SCA_REPORT_MAX_AGENTS} agents`,
    );
  }
  const response = await context.wazuh.api.client.asCurrentUser.request(
    'GET',
    '/agents',
    {
      params: {
        agents_list: requested.join(','), // eslint-disable-line camelcase
        select: 'id',
        limit: requested.length,
      },
    },
    { apiHostID: apiId },
  );
  const readable = new Set(
    (response?.data?.data?.affected_items || []).map((agent: { id?: string }) =>
      String(agent?.id ?? ''),
    ),
  );
  const authorized = requested.filter(agentId => readable.has(agentId));
  if (!authorized.length) {
    throw new ScaReportAgentsError(
      'None of the selected agents can be read with your permissions',
    );
  }
  return authorized;
}
