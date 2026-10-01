/*
 * Wazuh app - Queries of the SCA PDF report on the Wazuh 5.0 SCA states index
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/*
 * Every document of `wazuh-states-sca*` is the current state of one check of
 * one policy on one agent, so no "latest scan" reconstruction is needed (unlike
 * the 4.x alerts). The report pages through the checks with a composite
 * aggregation keyed by agent, policy and check; the per-policy totals are read
 * separately so the report can verify that every check was read.
 *
 * All the queries run as the current user, so the indexer security applies.
 */
import { WAZUH_SCA_PATTERN } from '../../../common/constants';

export const SCA_STATES_PAGE_SIZE = 1000;
const SCA_AGENT_AGGREGATION_LIMIT = 10000;
// Highest precision threshold supported by the cardinality aggregation; counts
// below it are exact.
const SCA_CHECKS_CARDINALITY_PRECISION = 40000;

const SCA_STATES_FIELDS = {
  AGENT_ID: 'wazuh.agent.id',
  AGENT_NAME: 'wazuh.agent.name',
  AGENT_IP: 'wazuh.agent.host.ip',
  POLICY_ID: 'policy.id',
  POLICY_NAME: 'policy.name',
  CHECK_ID: 'check.id',
  CHECK_RESULT: 'check.result',
  MODIFIED_AT: 'state.modified_at',
} as const;

const SCA_CHECK_SOURCE_FIELDS = [
  SCA_STATES_FIELDS.AGENT_ID,
  SCA_STATES_FIELDS.AGENT_NAME,
  SCA_STATES_FIELDS.AGENT_IP,
  SCA_STATES_FIELDS.POLICY_ID,
  SCA_STATES_FIELDS.POLICY_NAME,
  'check.id',
  'check.name',
  'check.result',
  'check.reason',
  'check.description',
  'check.rationale',
  'check.remediation',
  'check.compliance',
  SCA_STATES_FIELDS.MODIFIED_AT,
];

/**
 * Normalises a `check.result` value. The states index stores "Passed",
 * "Failed" and "Not applicable"; other spellings are accepted
 * case-insensitively. Unknown values are returned unchanged.
 */
export const normalizeScaResult = (result: unknown): string => {
  switch (
    String(result ?? '')
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
      return result ? String(result) : '-';
  }
};

export const normalizeAgentIds = (agentIds: string | string[]) => [
  ...new Set(
    (Array.isArray(agentIds) ? agentIds : [agentIds])
      .filter(Boolean)
      .map(agentId => String(agentId)),
  ),
];

export const buildScaStatesQuery = (
  agentIds: string | string[],
  { withCheck = false }: { withCheck?: boolean } = {},
) => ({
  bool: {
    filter: [
      { terms: { [SCA_STATES_FIELDS.AGENT_ID]: normalizeAgentIds(agentIds) } },
      ...(withCheck
        ? [
            { exists: { field: SCA_STATES_FIELDS.POLICY_ID } },
            { exists: { field: SCA_STATES_FIELDS.CHECK_ID } },
          ]
        : []),
    ],
  },
});

/** Fields of a SCA states document read by the report. */
export interface ScaStateDocument {
  wazuh?: {
    agent?: {
      id?: string;
      name?: string;
      host?: { ip?: string | string[] };
    };
  };
  policy?: { id?: string; name?: string };
  check?: {
    id?: string;
    name?: string;
    result?: string;
    reason?: string;
    description?: string;
    rationale?: string;
    remediation?: string;
    compliance?: Record<string, string[]>;
  };
  state?: { modified_at?: string };
}

export interface ScaCheckEntry {
  /** Composite key: agentId, policyId and checkId. */
  key: Record<string, string>;
  source: ScaStateDocument;
}

const getClient = context => context.core.opensearch.client.asCurrentUser;

const getAggregation = (response, name: string) =>
  response?.body?.aggregations?.[name] || response?.aggregations?.[name];

const firstValue = (value: unknown) =>
  Array.isArray(value) ? value.filter(Boolean).join(', ') : value;

export interface ScaAgentInventoryItem {
  id: string;
  name: string;
  ip: string;
  timestamp?: string;
}

/**
 * Name, IP and last SCA state change of the selected agents that have SCA
 * states.
 */
export async function getScaAgentInventory(
  context,
  agentIds: string | string[],
  pattern: string = WAZUH_SCA_PATTERN,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);
  const inventory = new Map<string, ScaAgentInventoryItem>();

  if (!normalizedAgentIds.length) {
    return inventory;
  }

  const response = await getClient(context).search({
    index: pattern,
    body: {
      size: 0,
      query: buildScaStatesQuery(normalizedAgentIds),
      aggs: {
        scaAgents: {
          terms: {
            field: SCA_STATES_FIELDS.AGENT_ID,
            size: Math.min(
              normalizedAgentIds.length,
              SCA_AGENT_AGGREGATION_LIMIT,
            ),
          },
          aggs: {
            latest: {
              // eslint-disable-next-line camelcase -- OpenSearch DSL
              top_hits: {
                size: 1,
                sort: [{ [SCA_STATES_FIELDS.MODIFIED_AT]: { order: 'desc' } }],
                _source: {
                  includes: [
                    SCA_STATES_FIELDS.AGENT_ID,
                    SCA_STATES_FIELDS.AGENT_NAME,
                    SCA_STATES_FIELDS.AGENT_IP,
                    SCA_STATES_FIELDS.MODIFIED_AT,
                  ],
                },
              },
            },
          },
        },
      },
    },
  });

  for (const bucket of getAggregation(response, 'scaAgents')?.buckets || []) {
    const source = bucket?.latest?.hits?.hits?.[0]?._source || {};
    const agent = source?.wazuh?.agent || {};
    const id = String(agent.id || bucket?.key || '');

    if (!id) {
      continue;
    }

    inventory.set(id, {
      id,
      name: agent.name || '',
      ip: String(firstValue(agent.host?.ip) || ''),
      timestamp: source?.state?.modified_at,
    });
  }

  return inventory;
}

export interface ScaPolicySummary {
  agentId: string;
  policyKey: string;
  policy: string;
  /** Distinct checks of the policy on the agent. */
  totalChecks: number | null;
  passed: number;
  failed: number;
  notApplicable: number;
  other: number;
  timestamp?: string;
}

/**
 * Per agent and policy totals computed by the indexer, keyed by
 * `${agentId}::${policyId}`.
 */
export async function getScaPolicySummaries(
  context,
  agentIds: string | string[],
  pattern: string = WAZUH_SCA_PATTERN,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);
  const summaries = new Map<string, ScaPolicySummary>();

  if (!normalizedAgentIds.length) {
    return summaries;
  }

  let afterKey: Record<string, string> | undefined;

  do {
    const composite: Record<string, unknown> = {
      size: SCA_STATES_PAGE_SIZE,
      sources: [
        { agentId: { terms: { field: SCA_STATES_FIELDS.AGENT_ID } } },
        { policyId: { terms: { field: SCA_STATES_FIELDS.POLICY_ID } } },
      ],
      ...(afterKey ? { after: afterKey } : {}),
    };

    // Pages are sequential: each request needs the previous after_key.
    // eslint-disable-next-line no-await-in-loop
    const response = await getClient(context).search({
      index: pattern,
      body: {
        size: 0,
        query: buildScaStatesQuery(normalizedAgentIds, { withCheck: true }),
        aggs: {
          scaPolicySummaries: {
            composite,
            aggs: {
              policyName: {
                terms: { field: SCA_STATES_FIELDS.POLICY_NAME, size: 1 },
              },
              checks: {
                cardinality: {
                  field: SCA_STATES_FIELDS.CHECK_ID,
                  // eslint-disable-next-line camelcase -- OpenSearch DSL
                  precision_threshold: SCA_CHECKS_CARDINALITY_PRECISION,
                },
              },
              results: {
                terms: {
                  field: SCA_STATES_FIELDS.CHECK_RESULT,
                  size: 20,
                  missing: '-',
                },
              },
              lastModified: {
                max: { field: SCA_STATES_FIELDS.MODIFIED_AT },
              },
            },
          },
        },
      },
    });

    const aggregation = getAggregation(response, 'scaPolicySummaries');
    const buckets = aggregation?.buckets || [];

    for (const bucket of buckets) {
      const agentId = String(bucket?.key?.agentId || '');
      const policyKey = String(bucket?.key?.policyId || '');

      if (!agentId || !policyKey) {
        continue;
      }

      const summary: ScaPolicySummary = {
        agentId,
        policyKey,
        policy: String(bucket?.policyName?.buckets?.[0]?.key || policyKey),
        totalChecks: Number.isFinite(Number(bucket?.checks?.value))
          ? Number(bucket.checks.value)
          : null,
        passed: 0,
        failed: 0,
        notApplicable: 0,
        other: 0,
        timestamp: bucket?.lastModified?.value_as_string,
      };

      for (const resultBucket of bucket?.results?.buckets || []) {
        const count = Number(resultBucket?.doc_count || 0);
        const result = normalizeScaResult(resultBucket?.key);

        if (result === 'Passed') {
          summary.passed += count;
        } else if (result === 'Failed') {
          summary.failed += count;
        } else if (result === 'Not applicable') {
          summary.notApplicable += count;
        } else {
          summary.other += count;
        }
      }

      summaries.set(`${agentId}::${policyKey}`, summary);
    }

    afterKey = buckets.length ? aggregation?.after_key : undefined;
  } while (afterKey);

  return summaries;
}

/**
 * Calls `onCheck` for every check of the selected agents, ordered by agent,
 * policy and check ID. When several documents hold the same check (for
 * example in two indices matched by the pattern), the last modified one wins.
 */
export async function forEachScaCheck(
  context,
  agentIds: string | string[],
  onCheck: (entry: ScaCheckEntry) => Promise<void> | void,
  pattern: string = WAZUH_SCA_PATTERN,
) {
  const normalizedAgentIds = normalizeAgentIds(agentIds);

  if (!normalizedAgentIds.length) {
    return;
  }

  let afterKey: Record<string, string> | undefined;

  do {
    const composite: Record<string, unknown> = {
      size: SCA_STATES_PAGE_SIZE,
      sources: [
        { agentId: { terms: { field: SCA_STATES_FIELDS.AGENT_ID } } },
        { policyId: { terms: { field: SCA_STATES_FIELDS.POLICY_ID } } },
        { checkId: { terms: { field: SCA_STATES_FIELDS.CHECK_ID } } },
      ],
      ...(afterKey ? { after: afterKey } : {}),
    };

    // Pages are sequential: each request needs the previous after_key.
    // eslint-disable-next-line no-await-in-loop
    const response = await getClient(context).search({
      index: pattern,
      body: {
        size: 0,
        query: buildScaStatesQuery(normalizedAgentIds, { withCheck: true }),
        aggs: {
          scaChecks: {
            composite,
            aggs: {
              latest: {
                // eslint-disable-next-line camelcase -- OpenSearch DSL
                top_hits: {
                  size: 1,
                  sort: [
                    { [SCA_STATES_FIELDS.MODIFIED_AT]: { order: 'desc' } },
                  ],
                  _source: { includes: SCA_CHECK_SOURCE_FIELDS },
                },
              },
            },
          },
        },
      },
    });

    const aggregation = getAggregation(response, 'scaChecks');
    const buckets = aggregation?.buckets || [];

    for (const bucket of buckets) {
      const source = bucket?.latest?.hits?.hits?.[0]?._source;

      if (!source) {
        continue;
      }

      // Checks are handled in order, so the report can render them in a stream.
      // eslint-disable-next-line no-await-in-loop
      await onCheck({ key: bucket.key || {}, source });
    }

    afterKey = buckets.length ? aggregation?.after_key : undefined;
  } while (afterKey);
}
