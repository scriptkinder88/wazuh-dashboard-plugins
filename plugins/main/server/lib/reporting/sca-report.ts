import { ReportPrinter } from './printer';

const SCA_REPORT_PAGE_SIZE = 500;
const AGENT_METADATA_BATCH_SIZE = 100;
// Keep report traffic below the default Wazuh API ceiling of 300 requests/minute.
const SCA_API_MIN_INTERVAL_MS = process.env.NODE_ENV === 'test' ? 0 : 250;
const SCA_API_RETRY_BASE_MS = process.env.NODE_ENV === 'test' ? 1 : 1000;
const SCA_API_MAX_RETRIES = 7;

let scaApiQueue: Promise<any> = Promise.resolve();
let lastScaApiRequestAt = 0;

const sleep = (milliseconds: number) =>
  new Promise(resolve => setTimeout(resolve, milliseconds));

const isRateLimitError = error => {
  const status =
    error?.status ||
    error?.statusCode ||
    error?.response?.status ||
    error?.response?.statusCode ||
    error?.data?.statusCode;
  const message = String(error?.message || error || '');

  return (
    Number(status) === 429 ||
    /status code 429|too many requests|rate.?limit/i.test(message)
  );
};

async function executeScaApiRequest(
  context,
  endpoint: string,
  apiId: string,
  params: any,
) {
  for (let attempt = 0; attempt <= SCA_API_MAX_RETRIES; attempt++) {
    const elapsed = Date.now() - lastScaApiRequestAt;
    const pacingDelay = Math.max(0, SCA_API_MIN_INTERVAL_MS - elapsed);

    if (pacingDelay) {
      await sleep(pacingDelay);
    }

    lastScaApiRequestAt = Date.now();

    try {
      return await context.wazuh.api.client.asCurrentUser.request(
        'GET',
        endpoint,
        { params },
        { apiHostID: apiId },
      );
    } catch (error) {
      if (!isRateLimitError(error) || attempt === SCA_API_MAX_RETRIES) {
        throw error;
      }

      const retryDelay = Math.min(
        SCA_API_RETRY_BASE_MS * Math.pow(2, attempt),
        30000,
      );

      context.wazuh.logger?.debug?.(
        `SCA report API rate limited on ${endpoint}. Retry ${
          attempt + 1
        }/${SCA_API_MAX_RETRIES} in ${retryDelay}ms`,
      );

      await sleep(retryDelay);
    }
  }
}

function scaApiRequest(context, endpoint: string, apiId: string, params: any) {
  const task = scaApiQueue
    .catch(() => undefined)
    .then(() => executeScaApiRequest(context, endpoint, apiId, params));

  scaApiQueue = task.then(
    () => undefined,
    () => undefined,
  );

  return task;
}

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

const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

const chunk = <T>(items: T[], size: number): T[][] => {
  const chunks: T[][] = [];

  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }

  return chunks;
};

async function fetchAllAffectedItems(context, endpoint, apiId, params = {}) {
  const items = [];
  let totalAffectedItems = null;

  do {
    const response = await scaApiRequest(context, endpoint, apiId, {
      ...params,
      offset: items.length,
      limit: SCA_REPORT_PAGE_SIZE,
    });

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

async function fetchAgentsMetadata(context, agentIds: string[], apiId: string) {
  const agentsById = new Map<string, any>();

  for (const agentBatch of chunk(agentIds, AGENT_METADATA_BATCH_SIZE)) {
    try {
      const response = await scaApiRequest(context, '/agents', apiId, {
        agents_list: agentBatch.join(','),
        limit: agentBatch.length,
        select: 'id,name,status,group,os.name,os.version',
      });

      const agents = response?.data?.data?.affected_items || [];

      agents.forEach(agent => {
        if (agent?.id) {
          agentsById.set(String(agent.id), agent);
        }
      });
    } catch (error) {
      context.wazuh.logger?.debug?.(
        `Unable to load metadata batch for SCA report: ${
          error.message || error
        }`,
      );
    }
  }

  return agentsById;
}

function formatOperatingSystem(agent: any) {
  return [agent?.os?.name, agent?.os?.version].filter(Boolean).join(' ') || '-';
}

function addAgentSectionHeader(
  printer: ReportPrinter,
  agentId: string,
  agent: any,
  addPageBreak: boolean,
) {
  if (addPageBreak) {
    printer.addContent({ text: '', pageBreak: 'before' });
  }

  const agentName = agent?.name || 'Unknown server';

  printer.addContentWithNewLine({
    text: `Server ${agentName} (${agentId})`,
    style: 'h2',
  });

  const details = [
    agent?.status ? `Status: ${agent.status}` : '',
    agent?.os?.name ? `Operating system: ${formatOperatingSystem(agent)}` : '',
    Array.isArray(agent?.group) && agent.group.length
      ? `Groups: ${agent.group.join(', ')}`
      : '',
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

export async function addScaChecksToReport(
  context,
  printer: ReportPrinter,
  agentIds: string | string[],
  apiId: string,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  printer.logger.debug(
    `Fetching SCA policies and checks for ${normalizedAgentIds.length} selected agents`,
  );

  const agentsById = await fetchAgentsMetadata(
    context,
    normalizedAgentIds,
    apiId,
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
      { id: 'status', label: 'Status' },
      { id: 'os', label: 'Operating system' },
    ],
    items: normalizedAgentIds.map(agentId => {
      const agent = agentsById.get(agentId);

      return {
        id: agentId,
        name: agent?.name || 'Unknown server',
        status: agent?.status || '-',
        os: formatOperatingSystem(agent),
      };
    }),
    widths: [45, 190, 70, '*'],
    fontSize: 7,
    maxTextLength: 42,
  });

  for (const agentId of normalizedAgentIds) {
    const agent = agentsById.get(agentId);

    addAgentSectionHeader(printer, agentId, agent, true);

    let policies = [];

    try {
      policies = await fetchAllAffectedItems(
        context,
        `/sca/${agentId}`,
        apiId,
        {
          sort: '+policy_id',
          select: 'policy_id,name,score,pass,fail,invalid',
        },
      );
    } catch (error) {
      printer.logger.debug(
        `Unable to load SCA policies for agent ${agentId}: ${
          error.message || error
        }`,
      );
      printer.addContentWithNewLine({
        text: 'Unable to retrieve SCA policies for this server.',
        style: 'standard',
      });
      continue;
    }

    if (!policies.length) {
      printer.addContentWithNewLine({
        text: 'No SCA policies or controls were found for this server.',
        style: 'standard',
      });
      continue;
    }

    for (const policy of policies) {
      const policyId = policy.policy_id;
      let checks = [];
      let checksError = false;

      try {
        checks = await fetchAllAffectedItems(
          context,
          `/sca/${agentId}/checks/${encodeURIComponent(policyId)}`,
          apiId,
          {
            sort: '+id',
            select: 'id,title,result,compliance.key,compliance.value',
          },
        );
      } catch (error) {
        checksError = true;
        printer.logger.debug(
          `Unable to load SCA checks for agent ${agentId}, policy ${policyId}: ${
            error.message || error
          }`,
        );
      }

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

      if (checksError) {
        printer.addContentWithNewLine({
          text: 'Unable to retrieve controls for this policy.',
          style: 'standard',
        });
        continue;
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
        widths: [42, 72, '*', 220],
        fontSize: 7,
        maxTextLength: 42,
      });
    }
  }
}
