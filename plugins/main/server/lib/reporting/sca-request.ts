import { cloneDeep } from 'lodash';
import {
  Aggregation,
  BoolQuery,
  CompositeBucket,
  CompositeKey,
  OpenSearchQuery,
  ScaAgentInfo,
  ScaCheckEntry,
  ScaPolicySummary,
  ScaSearchContext,
  ScaSearchResponse,
  TermsBucket,
} from './sca-types';

const SCA_COMPOSITE_PAGE_SIZE = 1000;
const SCA_AGENT_AGGREGATION_LIMIT = 10000;

const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

const ensureBoolQuery = (query?: OpenSearchQuery): BoolQuery => {
  const cloned = cloneDeep(query || {}) as Partial<BoolQuery>;

  if (cloned?.bool) {
    const filter: unknown = cloned.bool.filter;
    if (!Array.isArray(filter)) {
      cloned.bool.filter = filter ? [filter] : [];
    }

    return cloned as BoolQuery;
  }

  return {
    bool: {
      must: Object.keys(cloned || {}).length ? [cloned] : [],
      filter: [],
    },
  };
};

export const buildScaBaseIndexQuery = (
  serverSideQuery: OpenSearchQuery | undefined,
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
  );

  return query;
};

export const buildScaIndexQuery = (
  serverSideQuery: OpenSearchQuery | undefined,
  agentIds: string | string[],
) => {
  const query = buildScaBaseIndexQuery(serverSideQuery, agentIds);

  query.bool.filter.push({
    exists: {
      field: 'data.sca.check.id',
    },
  });

  return query;
};

export const buildScaSummaryIndexQuery = (
  serverSideQuery: OpenSearchQuery | undefined,
  agentIds: string | string[],
) => {
  const query = buildScaBaseIndexQuery(serverSideQuery, agentIds);

  query.bool.filter.push(
    {
      exists: {
        field: 'data.sca.policy',
      },
    },
    {
      exists: {
        field: 'data.sca.total_checks',
      },
    },
  );

  return query;
};

const getAggregation = <B>(
  response: ScaSearchResponse,
  name: string,
): Aggregation<B> | undefined =>
  (response?.body?.aggregations?.[name] || response?.aggregations?.[name]) as
    | Aggregation<B>
    | undefined;

export async function getScaAgentInventory(
  context: ScaSearchContext,
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  agentIds: string | string[],
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return new Map<string, ScaAgentInfo>();
  }

  const response = await context.core.opensearch.client.asCurrentUser.search({
    index: pattern,
    body: {
      size: 0,
      query: buildScaBaseIndexQuery(serverSideQuery, normalizedAgentIds),
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

  const buckets =
    getAggregation<TermsBucket>(response, 'sca_agents')?.buckets || [];
  const inventory = new Map<string, ScaAgentInfo>();

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

export async function getLatestScaPolicySummaries(
  context: ScaSearchContext,
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  agentIds: string | string[],
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);
  const summaries = new Map<string, ScaPolicySummary>();

  if (!normalizedAgentIds.length) {
    return summaries;
  }

  let afterKey: CompositeKey | undefined;

  do {
    const composite: Record<string, unknown> = {
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
      ],
    };

    if (afterKey) {
      composite.after = afterKey;
    }

    const response = await context.core.opensearch.client.asCurrentUser.search({
      index: pattern,
      body: {
        size: 0,
        query: buildScaSummaryIndexQuery(serverSideQuery, normalizedAgentIds),
        aggs: {
          sca_policy_summaries: {
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
                      'data.sca.total_checks',
                      'data.sca.passed',
                      'data.sca.failed',
                      'data.sca.invalid',
                      'data.sca.score',
                    ],
                  },
                },
              },
            },
          },
        },
      },
    });

    const aggregation = getAggregation<CompositeBucket>(
      response,
      'sca_policy_summaries',
    );
    const buckets = aggregation?.buckets || [];

    for (const bucket of buckets) {
      const source = bucket?.latest?.hits?.hits?.[0]?._source || {};
      const agentId = String(bucket?.key?.agent_id || source?.agent?.id || '');
      const policyKey = String(
        bucket?.key?.policy ||
          source?.data?.sca?.policy ||
          source?.data?.sca?.policy_id ||
          '',
      );

      if (!agentId || !policyKey) {
        continue;
      }

      const rawTotalChecks = source?.data?.sca?.total_checks;
      const parsedTotalChecks = Number(rawTotalChecks);

      summaries.set(`${agentId}::${policyKey}`, {
        agentId,
        policyKey,
        policy:
          source?.data?.sca?.policy || source?.data?.sca?.name || policyKey,
        totalChecks: Number.isFinite(parsedTotalChecks)
          ? parsedTotalChecks
          : null,
        passed: Number(source?.data?.sca?.passed || 0),
        failed: Number(source?.data?.sca?.failed || 0),
        invalid: Number(source?.data?.sca?.invalid || 0),
        score:
          source?.data?.sca?.score === null ||
          typeof source?.data?.sca?.score === 'undefined'
            ? null
            : Number(source?.data?.sca?.score),
        scanId: source?.data?.sca?.scan_id,
        timestamp: source?.timestamp,
      });
    }

    afterKey = buckets.length ? aggregation?.after_key : undefined;
  } while (afterKey);

  return summaries;
}

export async function forEachLatestScaCheck(
  context: ScaSearchContext,
  pattern: string,
  serverSideQuery: OpenSearchQuery | undefined,
  agentIds: string | string[],
  onCheck: (entry: ScaCheckEntry) => Promise<void> | void,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  let afterKey: CompositeKey | undefined;

  do {
    const composite: Record<string, unknown> = {
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
                      'data.sca.check.rationale',
                      'data.sca.check.remediation',
                      'data.sca.check.description',
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

    const aggregation = getAggregation<CompositeBucket>(response, 'sca_checks');
    const buckets = aggregation?.buckets || [];

    for (const bucket of buckets) {
      const source = bucket?.latest?.hits?.hits?.[0]?._source;

      if (!source) {
        continue;
      }

      // SCA check events are emitted only when a check changes. Keep the latest
      // known state even when its scan_id predates the latest summary.
      await onCheck({ key: bucket.key || {}, source });
    }

    afterKey = buckets.length ? aggregation?.after_key : undefined;
  } while (afterKey);
}

export const SCA_INDEX_COMPOSITE_PAGE_SIZE = SCA_COMPOSITE_PAGE_SIZE;
