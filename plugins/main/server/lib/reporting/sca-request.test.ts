import {
  buildScaIndexQuery,
  buildScaSummaryIndexQuery,
  forEachLatestScaCheck,
  getLatestScaPolicySummaries,
  getScaAgentInventory,
  SCA_INDEX_COMPOSITE_PAGE_SIZE,
} from './sca-request';

const buildContext = search => ({
  core: {
    opensearch: {
      client: {
        asCurrentUser: {
          search,
        },
      },
    },
  },
});

describe('SCA indexed reporting queries', () => {
  it('keeps existing authorization filters and intersects them with the selected servers', () => {
    const authorizedFilter = {
      terms: {
        'agent.id': ['003', '004', '005'],
      },
    };

    const query = buildScaIndexQuery(
      {
        bool: {
          must: [],
          filter: [authorizedFilter],
        },
      },
      ['003', '004'],
    );

    expect(query.bool.filter).toEqual(
      expect.arrayContaining([
        authorizedFilter,
        { term: { 'rule.groups': 'sca' } },
        { terms: { 'agent.id': ['003', '004'] } },
        { exists: { field: 'data.sca.check.id' } },
      ]),
    );
  });

  it('builds a scan-summary query without requiring a check event', () => {
    const query = buildScaSummaryIndexQuery(
      { bool: { must: [], filter: [] } },
      ['003', '004'],
    );

    expect(query.bool.filter).toEqual(
      expect.arrayContaining([
        { term: { 'rule.groups': 'sca' } },
        { terms: { 'agent.id': ['003', '004'] } },
        { exists: { field: 'data.sca.policy' } },
        { exists: { field: 'data.sca.total_checks' } },
      ]),
    );
    expect(query.bool.filter).not.toContainEqual({
      exists: { field: 'data.sca.check.id' },
    });
  });

  it('uses one indexed agent aggregation for a 600-server inventory', async () => {
    const agentIds = Array.from({ length: 600 }, (_, index) =>
      String(index + 1).padStart(3, '0'),
    );

    const search = jest.fn(async request => ({
      body: {
        aggregations: {
          sca_agents: {
            buckets: [
              {
                key: '003',
                latest: {
                  hits: {
                    hits: [
                      {
                        _source: {
                          agent: {
                            id: '003',
                            name: 'server-003',
                            ip: '10.0.0.3',
                          },
                          timestamp: '2026-09-24T10:00:00.000Z',
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
    }));

    const inventory = await getScaAgentInventory(
      buildContext(search),
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
      agentIds,
    );

    expect(search).toHaveBeenCalledTimes(1);
    const request = search.mock.calls[0][0];
    expect(request.index).toBe('wazuh-alerts-*');
    expect(request.body.query.bool.filter).toContainEqual({
      terms: { 'agent.id': agentIds },
    });
    expect(request.body.aggs.sca_agents.terms.size).toBe(600);
    expect(inventory.get('003')).toEqual(
      expect.objectContaining({
        id: '003',
        name: 'server-003',
      }),
    );
  });

  it('reads latest scan summaries in bulk for completeness validation', async () => {
    const search = jest
      .fn()
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            sca_policy_summaries: {
              buckets: [
                {
                  key: { agent_id: '003', policy: 'CIS Linux' },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            timestamp: '2026-09-24T10:00:00.000Z',
                            agent: { id: '003' },
                            data: {
                              sca: {
                                policy: 'CIS Linux',
                                policy_id: 'cis_linux',
                                total_checks: 200,
                                passed: 150,
                                failed: 40,
                                invalid: 10,
                                score: 78.9,
                                scan_id: 42,
                              },
                            },
                          },
                        },
                      ],
                    },
                  },
                },
              ],
              after_key: { agent_id: '003', policy: 'CIS Linux' },
            },
          },
        },
      })
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            sca_policy_summaries: {
              buckets: [
                {
                  key: { agent_id: '004', policy: 'CIS Windows' },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            timestamp: '2026-09-24T10:01:00.000Z',
                            agent: { id: '004' },
                            data: {
                              sca: {
                                policy: 'CIS Windows',
                                policy_id: 'cis_windows',
                                total_checks: 300,
                                passed: 250,
                                failed: 50,
                                invalid: 0,
                                score: 83.3,
                                scan_id: 99,
                              },
                            },
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

    const summaries = await getLatestScaPolicySummaries(
      buildContext(search),
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
      ['003', '004'],
    );

    expect(search).toHaveBeenCalledTimes(2);
    expect(
      search.mock.calls[0][0].body.aggs.sca_policy_summaries.composite.size,
    ).toBe(SCA_INDEX_COMPOSITE_PAGE_SIZE);
    expect(
      search.mock.calls[1][0].body.aggs.sca_policy_summaries.composite.after,
    ).toEqual({ agent_id: '003', policy: 'CIS Linux' });
    expect(summaries.get('003::CIS Linux')).toEqual(
      expect.objectContaining({
        agentId: '003',
        policyKey: 'CIS Linux',
        totalChecks: 200,
        passed: 150,
        failed: 40,
        invalid: 10,
        scanId: 42,
      }),
    );
    expect(summaries.get('004::CIS Windows')?.totalChecks).toBe(300);
  });

  it('paginates latest check state with composite aggregation instead of per-agent API calls', async () => {
    const search = jest
      .fn()
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            sca_checks: {
              buckets: [
                {
                  key: {
                    agent_id: '003',
                    policy: 'CIS Linux',
                    scan_id: 42,
                    check_id: '1',
                  },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            timestamp: '2026-09-24T10:00:00.000Z',
                            agent: { id: '003', name: 'server-003' },
                            data: {
                              sca: {
                                policy: 'CIS Linux',
                                scan_id: 42,
                                check: {
                                  id: '1',
                                  title: 'Control 1',
                                  result: 'passed',
                                },
                              },
                            },
                          },
                        },
                      ],
                    },
                  },
                },
              ],
              after_key: {
                agent_id: '003',
                policy: 'CIS Linux',
                scan_id: 42,
                check_id: '1',
              },
            },
          },
        },
      })
      .mockResolvedValueOnce({
        body: {
          aggregations: {
            sca_checks: {
              buckets: [
                {
                  key: {
                    agent_id: '004',
                    policy: 'CIS Windows',
                    scan_id: 99,
                    check_id: '2',
                  },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            timestamp: '2026-09-24T10:01:00.000Z',
                            agent: { id: '004', name: 'server-004' },
                            data: {
                              sca: {
                                policy: 'CIS Windows',
                                scan_id: 99,
                                check: {
                                  id: '2',
                                  title: 'Control 2',
                                  result: 'failed',
                                },
                              },
                            },
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

    const entries: any[] = [];
    const summaries = new Map([
      [
        '003::CIS Linux',
        { agentId: '003', policyKey: 'CIS Linux', scanId: 42 },
      ],
      [
        '004::CIS Windows',
        { agentId: '004', policyKey: 'CIS Windows', scanId: 99 },
      ],
    ]);

    await forEachLatestScaCheck(
      buildContext(search),
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
      ['003', '004'],
      summaries,
      entry => entries.push(entry),
    );

    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[0][0].body.aggs.sca_checks.composite.size).toBe(
      SCA_INDEX_COMPOSITE_PAGE_SIZE,
    );
    expect(
      search.mock.calls[1][0].body.aggs.sca_checks.composite.after,
    ).toEqual({
      agent_id: '003',
      policy: 'CIS Linux',
      scan_id: 42,
      check_id: '1',
    });
    expect(search.mock.calls[0][0].body.query.bool.filter).toContainEqual({
      terms: { 'data.sca.scan_id': [42, 99] },
    });
    expect(
      search.mock.calls[0][0].body.aggs.sca_checks.composite.sources,
    ).toEqual(
      expect.arrayContaining([
        {
          scan_id: {
            terms: {
              field: 'data.sca.scan_id',
            },
          },
        },
      ]),
    );
    expect(
      search.mock.calls[0][0].body.aggs.sca_checks.aggs.latest.top_hits._source
        .includes,
    ).toEqual(
      expect.arrayContaining([
        'data.sca.check.rationale',
        'data.sca.check.remediation',
        'data.sca.check.description',
        'data.sca.check.compliance',
      ]),
    );
    expect(entries.map(entry => entry.key.agent_id)).toEqual(['003', '004']);

    it('drops historical checks that are not part of the latest scan summary', async () => {
      const search = jest.fn(async () => ({
        body: {
          aggregations: {
            sca_checks: {
              buckets: [
                {
                  key: {
                    agent_id: '003',
                    policy: 'CIS Linux',
                    scan_id: 41,
                    check_id: '999',
                  },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            agent: { id: '003' },
                            data: {
                              sca: {
                                policy: 'CIS Linux',
                                scan_id: 41,
                                check: { id: '999', result: 'failed' },
                              },
                            },
                          },
                        },
                      ],
                    },
                  },
                },
                {
                  key: {
                    agent_id: '003',
                    policy: 'CIS Linux',
                    scan_id: 42,
                    check_id: '1',
                  },
                  latest: {
                    hits: {
                      hits: [
                        {
                          _source: {
                            agent: { id: '003' },
                            data: {
                              sca: {
                                policy: 'CIS Linux',
                                scan_id: 42,
                                check: { id: '1', result: 'passed' },
                              },
                            },
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
      }));

      const entries: any[] = [];

      await forEachLatestScaCheck(
        buildContext(search),
        'wazuh-alerts-*',
        { bool: { must: [], filter: [] } },
        ['003'],
        new Map([
          [
            '003::CIS Linux',
            { agentId: '003', policyKey: 'CIS Linux', scanId: 42 },
          ],
        ]),
        entry => entries.push(entry),
      );

      expect(entries).toHaveLength(1);
      expect(entries[0].key.check_id).toBe('1');
      expect(entries[0].key.scan_id).toBe(42);
    });
  });
});
