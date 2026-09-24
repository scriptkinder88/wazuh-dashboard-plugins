import { ReportPrinter } from './printer';
import { forEachLatestScaCheck, getScaAgentInventory } from './sca-request';

const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

const flattenComplianceValue = (value: any): string[] => {
  if (value === null || typeof value === 'undefined') {
    return [];
  }

  if (Array.isArray(value)) {
    return value.flatMap(flattenComplianceValue);
  }

  if (typeof value === 'object') {
    return Object.values(value).flatMap(flattenComplianceValue);
  }

  return String(value)
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
};

const formatCompliance = compliance => {
  if (!compliance) {
    return '-';
  }

  if (Array.isArray(compliance)) {
    const rows = compliance
      .map(item => {
        if (!item || typeof item !== 'object') {
          return String(item || '');
        }

        const key = item.key || '';
        const values = flattenComplianceValue(item.value);
        return [key, values.join(', ')].filter(Boolean).join(': ');
      })
      .filter(Boolean);

    return rows.length ? rows.join('\n') : '-';
  }

  if (typeof compliance === 'object') {
    const rows = Object.entries(compliance)
      .map(([key, value]) => {
        const values = flattenComplianceValue(value);
        return values.length ? `${key}: ${values.join(', ')}` : '';
      })
      .filter(Boolean);

    return rows.length ? rows.join('\n') : '-';
  }

  return String(compliance || '-');
};

const formatResult = result => {
  switch (
    String(result || '')
      .trim()
      .toLowerCase()
      .replace(/_/g, ' ')
  ) {
    case 'pass':
    case 'passed':
      return 'Passed';
    case 'fail':
    case 'failed':
      return 'Failed';
    case 'invalid':
    case 'not applicable':
      return 'Not applicable';
    default:
      return result || '-';
  }
};

function addAgentSectionHeader(
  printer: ReportPrinter,
  agentId: string,
  agent: any,
  addPageBreak: boolean,
) {
  if (addPageBreak) {
    printer.addContent({
      text: '',
      pageBreak: 'before',
      pageOrientation: 'landscape',
    });
  }

  const agentName = agent?.name || 'Unknown server';

  printer.addContentWithNewLine({
    text: `Server ${agentName} (${agentId})`,
    style: 'h2',
  });

  const details = [
    agent?.ip ? `IP: ${agent.ip}` : '',
    agent?.timestamp ? `Latest indexed SCA event: ${agent.timestamp}` : '',
  ]
    .filter(Boolean)
    .join(' | ');

  if (details) {
    printer.addContentWithNewLine({
      text: details,
      style: 'standard',
    });
  }
}

const createPolicyCounters = () => ({
  passed: 0,
  failed: 0,
  notApplicable: 0,
  other: 0,
});

export async function addScaChecksToReport(
  context,
  printer: ReportPrinter,
  agentIds: string | string[],
  pattern: string,
  serverSideQuery: any,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  printer.logger.debug(
    `Fetching indexed SCA controls for ${normalizedAgentIds.length} selected agents from ${pattern}`,
  );

  const inventory = await getScaAgentInventory(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
  );

  printer.addContent({
    text: 'Security configuration assessment controls',
    style: 'h1',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();

  printer.addSimpleTable({
    title: `Selected servers (${normalizedAgentIds.length})`,
    columns: [
      { id: 'id', label: 'ID' },
      { id: 'name', label: 'Server' },
      { id: 'ip', label: 'IP address' },
      { id: 'sca', label: 'Indexed SCA data' },
    ],
    items: normalizedAgentIds.map(agentId => {
      const agent = inventory.get(agentId);

      return {
        id: agentId,
        name: agent?.name || 'Unknown server',
        ip: agent?.ip || '-',
        sca: agent ? 'Available' : 'No indexed SCA data',
      };
    }),
    widths: [45, 210, 110, '*'],
    fontSize: 7,
    maxTextLength: 40,
  });

  const seenAgents = new Set<string>();
  let activeAgentId = '';
  let activePolicy = '';
  let activePolicyId = '';
  let activeAgent: any = null;
  let activeItems: any[] = [];
  let counters = createPolicyCounters();
  let renderedAgents = 0;

  const flushPolicy = () => {
    if (!activeAgentId || !activePolicy) {
      return;
    }

    const denominator = counters.passed + counters.failed;
    const score =
      denominator > 0
        ? Math.round((counters.passed / denominator) * 100)
        : null;

    printer.addContentWithNewLine({
      text:
        activePolicy ||
        (activePolicyId ? `Policy ${activePolicyId}` : 'SCA policy'),
      style: 'h3',
    });

    const summary = [
      score !== null ? `Score: ${score}%` : '',
      `Passed: ${counters.passed}`,
      `Failed: ${counters.failed}`,
      `Not applicable: ${counters.notApplicable}`,
      counters.other ? `Other: ${counters.other}` : '',
    ]
      .filter(Boolean)
      .join(' | ');

    printer.addContentWithNewLine({
      text: summary,
      style: 'standard',
    });

    printer.addSimpleTable({
      title: `Controls (${activeItems.length})`,
      columns: [
        { id: 'id', label: 'ID' },
        { id: 'result', label: 'Result' },
        { id: 'title', label: 'Control' },
        { id: 'compliance', label: 'Compliance' },
      ],
      items: activeItems,
      widths: [42, 72, '*', 220],
      fontSize: 7,
      maxTextLength: 38,
    });

    activeItems = [];
    counters = createPolicyCounters();
  };

  await forEachLatestScaCheck(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
    ({ key, source }) => {
      const agentId = String(key?.agent_id || source?.agent?.id || '');
      const policy = String(
        key?.policy || source?.data?.sca?.policy || 'Unknown SCA policy',
      );
      const policyId = String(source?.data?.sca?.policy_id || '');

      if (!agentId) {
        return;
      }

      if (agentId !== activeAgentId) {
        flushPolicy();

        activeAgentId = agentId;
        activePolicy = '';
        activePolicyId = '';
        activeAgent = {
          ...(inventory.get(agentId) || {}),
          ...(source?.agent || {}),
          timestamp:
            source?.timestamp || inventory.get(agentId)?.timestamp || undefined,
        };

        addAgentSectionHeader(
          printer,
          agentId,
          activeAgent,
          renderedAgents > 0,
        );
        renderedAgents++;
        seenAgents.add(agentId);
      }

      if (policy !== activePolicy) {
        flushPolicy();
        activePolicy = policy;
        activePolicyId = policyId;
      }

      const rawResult =
        source?.data?.sca?.check?.result ||
        source?.data?.sca?.check?.status ||
        '-';
      const result = formatResult(rawResult);

      if (result === 'Passed') {
        counters.passed++;
      } else if (result === 'Failed') {
        counters.failed++;
      } else if (result === 'Not applicable') {
        counters.notApplicable++;
      } else {
        counters.other++;
      }

      activeItems.push({
        id: String(key?.check_id || source?.data?.sca?.check?.id || '-'),
        result,
        title: source?.data?.sca?.check?.title || '-',
        compliance: formatCompliance(source?.data?.sca?.check?.compliance),
      });
    },
  );

  flushPolicy();

  for (const agentId of normalizedAgentIds) {
    if (seenAgents.has(agentId)) {
      continue;
    }

    addAgentSectionHeader(
      printer,
      agentId,
      inventory.get(agentId),
      renderedAgents > 0,
    );
    renderedAgents++;

    printer.addContentWithNewLine({
      text: 'No indexed SCA controls were found for this server.',
      style: 'standard',
    });
  }
}
