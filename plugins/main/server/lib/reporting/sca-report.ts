import { ReportPrinter } from './printer';

const SCA_REPORT_PAGE_SIZE = 100;

const formatCompliance = compliance => {
  if (!Array.isArray(compliance) || !compliance.length) {
    return '-';
  }

  return compliance
    .map(item => {
      if (!item || typeof item !== 'object') {
        return String(item || '-');
      }

      const key = item.key || '';
      const value = item.value || '';

      return [key, value].filter(Boolean).join(': ') || '-';
    })
    .join('\n');
};

const formatResult = result => {
  switch (String(result || '').toLowerCase()) {
    case 'passed':
      return 'Passed';
    case 'failed':
      return 'Failed';
    case 'not applicable':
      return 'Not applicable';
    default:
      return result || '-';
  }
};

async function fetchAllAffectedItems(context, endpoint, apiId, params = {}) {
  const items = [];
  let totalAffectedItems = null;

  do {
    const response = await context.wazuh.api.client.asCurrentUser.request(
      'GET',
      endpoint,
      {
        params: {
          ...params,
          offset: items.length,
          limit: SCA_REPORT_PAGE_SIZE,
        },
      },
      { apiHostID: apiId },
    );

    const data = response?.data?.data || {};
    const page = data.affected_items || [];

    items.push(...page);

    if (typeof data.total_affected_items === 'number') {
      totalAffectedItems = data.total_affected_items;
    } else {
      totalAffectedItems = items.length;
    }

    if (!page.length) {
      break;
    }
  } while (items.length < totalAffectedItems);

  return items;
}

export async function addScaChecksToReport(
  context,
  printer: ReportPrinter,
  agentId: string,
  apiId: string,
) {
  printer.logger.debug(`Fetching SCA policies and checks for agent ${agentId}`);

  const policies = await fetchAllAffectedItems(
    context,
    `/sca/${agentId}`,
    apiId,
    { sort: '+policy_id' },
  );

  if (!policies.length) {
    printer.addContentWithNewLine({
      text: 'No SCA policies or controls were found for this agent.',
      style: 'standard',
    });
    return;
  }

  printer.addContentWithNewLine({
    text: 'Security configuration assessment controls',
    style: 'h2',
  });

  for (const policy of policies) {
    const policyId = policy.policy_id;
    const checks = await fetchAllAffectedItems(
      context,
      `/sca/${agentId}/checks/${encodeURIComponent(policyId)}`,
      apiId,
      { sort: '+id' },
    );

    printer.addContentWithNewLine({
      text: policy.name || `Policy ${policyId}`,
      style: 'h3',
    });

    const summary = [
      typeof policy.score !== 'undefined' ? `Score: ${policy.score}%` : '',
      typeof policy.pass !== 'undefined' ? `Passed: ${policy.pass}` : '',
      typeof policy.fail !== 'undefined' ? `Failed: ${policy.fail}` : '',
      typeof policy.invalid !== 'undefined'
        ? `Not applicable: ${policy.invalid}`
        : '',
    ]
      .filter(Boolean)
      .join(' | ');

    if (summary) {
      printer.addContentWithNewLine({
        text: summary,
        style: 'standard',
      });
    }

    printer.addSimpleTable({
      title: `Controls (${checks.length})`,
      columns: [
        { id: 'id', label: 'ID' },
        { id: 'result', label: 'Result' },
        { id: 'title', label: 'Control' },
        { id: 'compliance', label: 'Compliance' },
      ],
      items: checks.map(check => ({
        id:
          typeof check.id !== 'undefined' && check.id !== null
            ? String(check.id)
            : '-',
        result: formatResult(check.result),
        title: check.title || '-',
        compliance: formatCompliance(check.compliance),
      })),
    });
  }
}
