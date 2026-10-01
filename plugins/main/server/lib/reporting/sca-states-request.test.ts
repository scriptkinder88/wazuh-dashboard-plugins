/* eslint-disable camelcase -- OpenSearch DSL and responses */
import {
  buildScaStatesQuery,
  forEachScaCheck,
  getScaAgentInventory,
  getScaPolicySummaries,
  normalizeScaResult,
  SCA_STATES_PAGE_SIZE,
} from './sca-states-request';

const createContext = (search: jest.Mock) => ({
  core: { opensearch: { client: { asCurrentUser: { search } } } },
});

describe('SCA states requests', () => {
  it('normalises the check results case-insensitively', () => {
    expect(normalizeScaResult('Passed')).toBe('Passed');
    expect(normalizeScaResult('passed')).toBe('Passed');
    expect(normalizeScaResult('FAILED')).toBe('Failed');
    expect(normalizeScaResult('Not applicable')).toBe('Not applicable');
    expect(normalizeScaResult('not_applicable')).toBe('Not applicable');
    expect(normalizeScaResult('invalid')).toBe('Not applicable');
    expect(normalizeScaResult('Unknown')).toBe('Unknown');
    expect(normalizeScaResult(undefined)).toBe('-');
  });

  it('filters by the selected agents with a terms query', () => {
    expect(buildScaStatesQuery(['001', '002', '001'])).toEqual({
      bool: { filter: [{ terms: { 'wazuh.agent.id': ['001', '002'] } }] },
    });
    expect(buildScaStatesQuery('003', { withCheck: true }).bool.filter).toEqual(
      [
        { terms: { 'wazuh.agent.id': ['003'] } },
        { exists: { field: 'policy.id' } },
        { exists: { field: 'check.id' } },
      ],
    );
  });

  it('does not query without agents', async () => {
    const search = jest.fn();
    const context = createContext(search);

    expect((await getScaAgentInventory(context, [])).size).toBe(0);
    expect((await getScaPolicySummaries(context, [])).size).toBe(0);
    await forEachScaCheck(context, [], jest.fn());
    expect(search).not.toHaveBeenCalled();
  });

  it('reads the agent inventory from the states index', async () => {
    const search = jest.fn().mockResolvedValue({
      body: {
        aggregations: {
          scaAgents: {
            buckets: [
              {
                key: '001',
                latest: {
                  hits: {
                    hits: [
                      {
                        _source: {
                          wazuh: {
                            agent: {
                              id: '001',
                              name: 'web-01',
                              host: { ip: ['10.0.0.1', '10.0.0.2'] },
                            },
                          },
                          state: { modified_at: '2026-09-30T10:00:00.000Z' },
                        },
                      },
                    ],
                  },
                },
              },
            ],
          },
        },
      },
    });

    const inventory = await getScaAgentInventory(createContext(search), [
      '001',
      '002',
    ]);

    expect(search).toHaveBeenCalledTimes(1);
    const [{ index, body }] = search.mock.calls[0];
    expect(index).toBe('wazuh-states-sca*');
    expect(body.size).toBe(0);
    expect(body.query).toEqual(buildScaStatesQuery(['001', '002']));
    expect(body.aggs.scaAgents.terms).toEqual({
      field: 'wazuh.agent.id',
      size: 2,
    });
    expect(body.aggs.scaAgents.aggs.latest.top_hits.sort).toEqual([
      { 'state.modified_at': { order: 'desc' } },
    ]);
    expect(inventory.get('001')).toEqual({
      id: '001',
      name: 'web-01',
      ip: '10.0.0.1, 10.0.0.2',
      timestamp: '2026-09-30T10:00:00.000Z',
    });
    expect(inventory.has('002')).toBe(false);
  });

  it('pages the per-policy summaries and counts the results', async () => {
    const search = jest
      .fn()
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            scaPolicySummaries: {
              after_key: { agentId: '001', policyId: 'cis_rhel9_linux' },
              buckets: [
                {
                  key: { agentId: '001', policyId: 'cis_rhel9_linux' },
                  policyName: {
                    buckets: [{ key: 'CIS Red Hat Enterprise Linux 9' }],
                  },
                  checks: { value: 5 },
                  results: {
                    buckets: [
                      { key: 'Passed', doc_count: 2 },
                      { key: 'failed', doc_count: 1 },
                      { key: 'Not applicable', doc_count: 1 },
                      { key: '-', doc_count: 1 },
                    ],
                  },
                  lastModified: {
                    value_as_string: '2026-09-30T10:00:00.000Z',
                  },
                },
              ],
            },
          },
        },
      })
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            scaPolicySummaries: { buckets: [] },
          },
        },
      });

    const summaries = await getScaPolicySummaries(createContext(search), [
      '001',
    ]);

    expect(search).toHaveBeenCalledTimes(2);
    const firstComposite =
      search.mock.calls[0][0].body.aggs.scaPolicySummaries.composite;
    expect(firstComposite.size).toBe(SCA_STATES_PAGE_SIZE);
    expect(firstComposite.after).toBeUndefined();
    expect(firstComposite.sources).toEqual([
      { agentId: { terms: { field: 'wazuh.agent.id' } } },
      { policyId: { terms: { field: 'policy.id' } } },
    ]);
    expect(
      search.mock.calls[1][0].body.aggs.scaPolicySummaries.composite.after,
    ).toEqual({ agentId: '001', policyId: 'cis_rhel9_linux' });
    expect(summaries.get('001::cis_rhel9_linux')).toEqual({
      agentId: '001',
      policyKey: 'cis_rhel9_linux',
      policy: 'CIS Red Hat Enterprise Linux 9',
      totalChecks: 5,
      passed: 2,
      failed: 1,
      notApplicable: 1,
      other: 1,
      timestamp: '2026-09-30T10:00:00.000Z',
    });
  });

  it('iterates every check of the selected agents with a composite aggregation', async () => {
    const hit = (agentId: string, checkId: string) => ({
      key: { agentId, policyId: 'cis_rhel9_linux', checkId },
      latest: {
        hits: {
          hits: [
            {
              _source: {
                wazuh: { agent: { id: agentId } },
                policy: { id: 'cis_rhel9_linux' },
                check: { id: checkId, result: 'Passed' },
              },
            },
          ],
        },
      },
    });
    const search = jest
      .fn()
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            scaChecks: {
              after_key: { agentId: '001', checkId: '2' },
              buckets: [hit('001', '1'), hit('001', '2')],
            },
          },
        },
      })
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            scaChecks: {
              after_key: { agentId: '002', checkId: '1' },
              buckets: [hit('002', '1'), { key: {}, latest: { hits: {} } }],
            },
          },
        },
      })
      .mockResolvedValueOnce({
        body: { aggregations: { scaChecks: { buckets: [] } } },
      });
    const onCheck = jest.fn();

    await forEachScaCheck(createContext(search), ['001', '002'], onCheck);

    expect(search).toHaveBeenCalledTimes(3);
    const { body } = search.mock.calls[0][0];
    expect(body.query).toEqual(
      buildScaStatesQuery(['001', '002'], { withCheck: true }),
    );
    expect(body.aggs.scaChecks.composite.sources).toEqual([
      { agentId: { terms: { field: 'wazuh.agent.id' } } },
      { policyId: { terms: { field: 'policy.id' } } },
      { checkId: { terms: { field: 'check.id' } } },
    ]);
    expect(body.aggs.scaChecks.aggs.latest.top_hits._source.includes).toEqual(
      expect.arrayContaining(['check.name', 'check.result', 'policy.name']),
    );
    expect(search.mock.calls[2][0].body.aggs.scaChecks.composite.after).toEqual(
      { agentId: '002', checkId: '1' },
    );
    expect(onCheck.mock.calls.map(([{ key }]) => key.checkId)).toEqual([
      '1',
      '2',
      '1',
    ]);
  });
});
