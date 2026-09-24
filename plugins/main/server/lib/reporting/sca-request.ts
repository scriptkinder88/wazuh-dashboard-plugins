import { cloneDeep } from 'lodash';

const SCA_COMPOSITE_PAGE_SIZE = 1000;
const SCA_AGENT_AGGREGATION_LIMIT = 10000;

const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

const ensureBoolQuery = query => {
  const cloned = cloneDeep(query || {});

  if (cloned?.bool) {
    cloned.bool.filter = Array.isArray(cloned.bool.filter)
      ? cloned.bool.filter
      : cloned.bool.filter
      ? [cloned.bool.filter]
      : [];

    return cloned;
  }

  return {
    bool: {
      must: Object.keys(cloned || {}).length ? [cloned] : [],
      filter: [],
    },
  };
};

export const buildScaIndexQuery = (
  serverSideQuery: any,
  agentIds: string | string[],
) => {
  const normalizedAgentIds = normalizeAgentIds(agentIds);
  const query = ensureBoolQuery(serverSideQuery);

  query.bool.filter.push(
    {
      term: {
        'rule.groups': 'sca',
      },
    },
    {
      terms: {
        'agent.id': normalizedAgentIds,
      },
    },
    {
      exists: {
        field: 'data.sca.check.id',
      },
    },
  );

  return query;
};

const getAggregation = (response, name: string) =>
  response?.body?.aggregations?.[name] || response?.aggregations?.[name];

export async function getScaAgentInventory(
  context,
  pattern: string,
  serverSideQuery: any,
  agentIds: string | string[],
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return new Map<string, any>();
  }

  const response = await context.core.opensearch.client.asCurrentUser.search({
    index: pattern,
    body: {
      size: 0,
      query: buildScaIndexQuery(serverSideQuery, normalizedAgentIds),
      aggs: {
        sca_agents: {
          terms: {
            field: 'agent.id',
            size: Math.min(
              Math.max(normalizedAgentIds.length, 1),
              SCA_AGENT_AGGREGATION_LIMIT,
            ),
          },
          aggs: {
            latest: {
              top_hits: {
                size: 1,
                sort: [{ timestamp: { order: 'desc' } }],
                _source: {
                  includes: ['agent.id', 'agent.name', 'agent.ip', 'timestamp'],
                },
              },
            },
          },
        },
      },
    },
  });

  const buckets = getAggregation(response, 'sca_agents')?.buckets || [];
  const inventory = new Map<string, any>();

  for (const bucket of buckets) {
    const source = bucket?.latest?.hits?.hits?.[0]?._source || {};
    const id = String(source?.agent?.id || bucket?.key || '');

    if (!id) {
      continue;
    }

    inventory.set(id, {
      id,
      name: source?.agent?.name || '',
      ip: source?.agent?.ip || '',
      timestamp: source?.timestamp,
    });
  }

  return inventory;
}

export async function forEachLatestScaCheck(
  context,
  pattern: string,
  serverSideQuery: any,
  agentIds: string | string[],
  onCheck: (entry: { key: any; source: any }) => Promise<void> | void,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  let afterKey: any = undefined;

  do {
    const composite: any = {
      size: SCA_COMPOSITE_PAGE_SIZE,
      sources: [
        {
          agent_id: {
            terms: {
              field: 'agent.id',
            },
          },
        },
        {
          policy: {
            terms: {
              field: 'data.sca.policy',
            },
          },
        },
        {
          check_id: {
            terms: {
              field: 'data.sca.check.id',
            },
          },
        },
      ],
    };

    if (afterKey) {
      composite.after = afterKey;
    }

    const response = await context.core.opensearch.client.asCurrentUser.search({
      index: pattern,
      body: {
        size: 0,
        query: buildScaIndexQuery(serverSideQuery, normalizedAgentIds),
        aggs: {
          sca_checks: {
            composite,
            aggs: {
              latest: {
                top_hits: {
                  size: 1,
                  sort: [{ timestamp: { order: 'desc' } }],
                  _source: {
                    includes: [
                      'timestamp',
                      'agent.id',
                      'agent.name',
                      'agent.ip',
                      'data.sca.scan_id',
                      'data.sca.policy',
                      'data.sca.policy_id',
                      'data.sca.check.id',
                      'data.sca.check.title',
                      'data.sca.check.result',
                      'data.sca.check.status',
                      'data.sca.check.reason',
                      'data.sca.check.compliance',
                    ],
                  },
                },
              },
            },
          },
        },
      },
    });

    const aggregation = getAggregation(response, 'sca_checks');
    const buckets = aggregation?.buckets || [];

    for (const bucket of buckets) {
      const source = bucket?.latest?.hits?.hits?.[0]?._source;

      if (source) {
        await onCheck({ key: bucket.key || {}, source });
      }
    }

    afterKey = buckets.length ? aggregation?.after_key : undefined;
  } while (afterKey);
}

export const SCA_INDEX_COMPOSITE_PAGE_SIZE = SCA_COMPOSITE_PAGE_SIZE;
