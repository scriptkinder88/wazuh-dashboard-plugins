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

const addResultToCounters = (counters, result: string) => {
  if (result === 'Passed') {
    counters.passed++;
  } else if (result === 'Failed') {
    counters.failed++;
  } else if (result === 'Not applicable') {
    counters.notApplicable++;
  } else {
    counters.other++;
  }
};

const getCountersTotal = counters =>
  counters.passed +
  counters.failed +
  counters.notApplicable +
  counters.other;

const getCountersScore = counters => {
  const denominator = counters.passed + counters.failed;

  return denominator > 0
    ? Math.round((counters.passed / denominator) * 100)
    : null;
};

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

  const overallCounters = createPolicyCounters();
  const serverSummaries = new Map<string, any>();
  const policySummaries = new Map<string, any>();

  for (const agentId of normalizedAgentIds) {
    const agent = inventory.get(agentId);
    serverSummaries.set(agentId, {
      id: agentId,
      name: agent?.name || 'Unknown server',
      ip: agent?.ip || '-',
      ...createPolicyCounters(),
    });
  }

  await forEachLatestScaCheck(
    context,
    pattern,
    serverSideQuery,
    normalizedAgentIds,
    ({ key, source }) => {
      const agentId = String(key?.agent_id || source?.agent?.id || '');
      const policy = String(source?.data?.sca?.policy || 'Unknown SCA policy');
      const policyKey = String(
        key?.policy_id || source?.data?.sca?.policy_id || policy,
      );
      const rawResult =
        source?.data?.sca?.check?.result ||
        source?.data?.sca?.check?.status ||
        '-';
      const result = formatResult(rawResult);

      if (!agentId) {
        return;
      }

      if (!serverSummaries.has(agentId)) {
        serverSummaries.set(agentId, {
          id: agentId,
          name: source?.agent?.name || 'Unknown server',
          ip: source?.agent?.ip || '-',
          ...createPolicyCounters(),
        });
      }

      const serverSummary = serverSummaries.get(agentId);
      addResultToCounters(serverSummary, result);
      addResultToCounters(overallCounters, result);

      if (!policySummaries.has(policyKey)) {
        policySummaries.set(policyKey, {
          key: policyKey,
          policy,
          agents: new Set<string>(),
          ...createPolicyCounters(),
        });
      }

      const policySummary = policySummaries.get(policyKey);
      policySummary.agents.add(agentId);
      addResultToCounters(policySummary, result);
    },
  );

  const serversWithData = Array.from(serverSummaries.values()).filter(
    summary => getCountersTotal(summary) > 0,
  ).length;
  const overallScore = getCountersScore(overallCounters);

  printer.addContent({
    text: 'Security configuration assessment controls',
    style: 'h1',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();

  printer.addSimpleTable({
    title: 'Grouped SCA result',
    columns: [
      { id: 'selected', label: 'Selected' },
      { id: 'withData', label: 'With SCA data' },
      { id: 'withoutData', label: 'Without data' },
      { id: 'controls', label: 'Controls' },
      { id: 'passed', label: 'Passed' },
      { id: 'failed', label: 'Failed' },
      { id: 'notApplicable', label: 'N/A' },
      { id: 'score', label: 'Score' },
    ],
    items: [
      {
        selected: normalizedAgentIds.length,
        withData: serversWithData,
        withoutData: normalizedAgentIds.length - serversWithData,
        controls: getCountersTotal(overallCounters),
        passed: overallCounters.passed,
        failed: overallCounters.failed,
        notApplicable: overallCounters.notApplicable,
        score: overallScore === null ? '-' : `${overallScore}%`,
      },
    ],
    widths: [55, 70, 70, 65, 55, 55, 55, 55],
    fontSize: 7,
    maxTextLength: 24,
  });

  printer.addSimpleTable({
    title: `Selected server results (${normalizedAgentIds.length})`,
    columns: [
      { id: 'id', label: 'ID' },
      { id: 'name', label: 'Server' },
      { id: 'score', label: 'Score' },
      { id: 'passed', label: 'Passed' },
      { id: 'failed', label: 'Failed' },
      { id: 'notApplicable', label: 'N/A' },
      { id: 'controls', label: 'Controls' },
      { id: 'sca', label: 'Indexed SCA data' },
    ],
    items: normalizedAgentIds.map(agentId => {
      const summary = serverSummaries.get(agentId);
      const controls = getCountersTotal(summary);
      const score = getCountersScore(summary);

      return {
        id: agentId,
        name: summary?.name || 'Unknown server',
        score: score === null ? '-' : `${score}%`,
        passed: summary?.passed || 0,
        failed: summary?.failed || 0,
        notApplicable: summary?.notApplicable || 0,
        controls,
        sca: controls ? 'Available' : 'No indexed SCA data',
      };
    }),
    widths: [42, 150, 52, 52, 52, 52, 60, '*'],
    fontSize: 7,
    maxTextLength: 32,
  });

  if (policySummaries.size) {
    printer.addSimpleTable({
      title: `Grouped by policy (${policySummaries.size})`,
      columns: [
        { id: 'policy', label: 'Policy' },
        { id: 'servers', label: 'Servers' },
        { id: 'controls', label: 'Controls' },
        { id: 'passed', label: 'Passed' },
        { id: 'failed', label: 'Failed' },
        { id: 'notApplicable', label: 'N/A' },
        { id: 'score', label: 'Score' },
      ],
      items: Array.from(policySummaries.values())
        .sort((a, b) => String(a.policy).localeCompare(String(b.policy)))
        .map(summary => {
          const score = getCountersScore(summary);

          return {
            policy: summary.policy,
            servers: summary.agents.size,
            controls: getCountersTotal(summary),
            passed: summary.passed,
            failed: summary.failed,
            notApplicable: summary.notApplicable,
            score: score === null ? '-' : `${score}%`,
          };
        }),
      widths: ['*', 55, 60, 55, 55, 55, 55],
      fontSize: 7,
      maxTextLength: 44,
    });
  }

  printer.addContent({
    text: 'Detailed results by selected server',
    style: 'h2',
    pageBreak: 'before',
    pageOrientation: 'landscape',
  });
  printer.addNewLine();

  const seenAgents = new Set<string>();
  let activeAgentId = '';
  let activePolicy = '';
  let activePolicyKey = '';
  let activeAgent: any = null;
  let activeItems: any[] = [];
  let counters = createPolicyCounters();
  let renderedAgents = 0;

  const flushPolicy = () => {
    if (!activeAgentId || !activePolicy) {
      return;
    }

    const score = getCountersScore(counters);

    printer.addContentWithNewLine({
      text:
        activePolicy ||
        (activePolicyKey ? `Policy ${activePolicyKey}` : 'SCA policy'),
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
      const policy = String(source?.data?.sca?.policy || 'Unknown SCA policy');
      const policyKey = String(
        key?.policy_id || source?.data?.sca?.policy_id || policy,
      );

      if (!agentId) {
        return;
      }

      if (agentId !== activeAgentId) {
        flushPolicy();

        activeAgentId = agentId;
        activePolicy = '';
        activePolicyKey = '';
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

      if (policyKey !== activePolicyKey) {
        flushPolicy();
        activePolicy = policy;
        activePolicyKey = policyKey;
      }

      const rawResult =
        source?.data?.sca?.check?.result ||
        source?.data?.sca?.check?.status ||
        '-';
      const result = formatResult(rawResult);

      addResultToCounters(counters, result);

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
