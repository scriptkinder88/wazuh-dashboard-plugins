import { addScaChecksToReport } from './sca-report';

const createPrinter = () => ({
  logger: {
    debug: jest.fn(),
  },
  addContent: jest.fn().mockReturnThis(),
  addContentWithNewLine: jest.fn().mockReturnThis(),
  addSimpleTable: jest.fn().mockReturnThis(),
  addNewLine: jest.fn().mockReturnThis(),
});

const policyId = (policy: string) => policy.toLowerCase().replace(/\s+/g, '_');

const inventoryBucket = (id: string) => ({
  key: id,
  latest: {
    hits: {
      hits: [
        {
          _source: {
            agent: {
              id,
              name: `server-${id}`,
              ip: `10.0.0.${Number(id)}`,
            },
            timestamp: '2026-09-24T10:00:00.000Z',
          },
        },
      ],
    },
  },
});

const summaryBucket = (
  agentId: string,
  policy: string,
  totalChecks: number,
  passed = 0,
  failed = 0,
  invalid = 0,
) => ({
  key: {
    agent_id: agentId,
    policy,
  },
  latest: {
    hits: {
      hits: [
        {
          _source: {
            timestamp: '2026-09-24T10:00:00.000Z',
            agent: {
              id: agentId,
              name: `server-${agentId}`,
            },
            data: {
              sca: {
                policy,
                policy_id: policyId(policy),
                total_checks: totalChecks,
                passed,
                failed,
                invalid,
                scan_id: 42,
              },
            },
          },
        },
      ],
    },
  },
});

const checkBucket = (
  agentId: string,
  policy: string,
  checkId: string,
  result: string,
  compliance: any = {},
) => ({
  key: {
    agent_id: agentId,
    policy,
    check_id: checkId,
  },
  latest: {
    hits: {
      hits: [
        {
          _source: {
            timestamp: '2026-09-24T10:00:00.000Z',
            agent: {
              id: agentId,
              name: `server-${agentId}`,
              ip: `10.0.0.${Number(agentId)}`,
            },
            data: {
              sca: {
                policy,
                policy_id: policyId(policy),
                check: {
                  id: checkId,
                  title: `Control ${checkId}`,
                  result,
                  compliance,
                },
              },
            },
          },
        },
      ],
    },
  },
});

const buildContext = (
  inventoryBuckets: any[],
  checkBuckets: any[],
  summaryBuckets: any[] = [],
) => {
  const search = jest.fn(async request => {
    if (request.body.aggs.sca_agents) {
      return {
        body: {
          aggregations: {
            sca_agents: {
              buckets: inventoryBuckets,
            },
          },
        },
      };
    }

    if (request.body.aggs.sca_policy_summaries) {
      return {
        body: {
          aggregations: {
            sca_policy_summaries: {
              buckets: summaryBuckets,
            },
          },
        },
      };
    }

    if (request.body.aggs.sca_checks) {
      return {
        body: {
          aggregations: {
            sca_checks: {
              buckets: checkBuckets,
            },
          },
        },
      };
    }

    throw new Error('Unexpected OpenSearch request');
  });

  return {
    context: {
      core: {
        opensearch: {
          client: {
            asCurrentUser: {
              search,
            },
          },
        },
      },
    },
    search,
  };
};

describe('SCA indexed report controls', () => {
  it('renders verified indexed controls with constrained landscape columns', async () => {
    const policy = 'CIS Linux benchmark';
    const { context, search } = buildContext(
      [inventoryBucket('003')],
      [
        checkBucket('003', policy, '1', 'failed', {
          cis: '1.1.1',
          pci_dss_v4: { 0: '2.2.1,2.2.2' },
        }),
        checkBucket('003', policy, '2', 'not applicable'),
        checkBucket('003', policy, '3', 'passed'),
      ],
      [summaryBucket('003', policy, 3, 1, 1, 1)],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      '003',
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    expect(search).toHaveBeenCalledTimes(4);
    expect(printer.addContent).toHaveBeenCalledWith(
      expect.objectContaining({
        text: 'Security configuration assessment controls',
        pageBreak: 'before',
        pageOrientation: 'landscape',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith(
      expect.objectContaining({
        text: expect.stringContaining(
          'verified against the latest scan total_checks',
        ),
      }),
    );

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const assessmentScope = tables.find(
      table => table.title === 'Assessment scope',
    );
    const controlOutcome = tables.find(
      table => table.title === 'Control outcome',
    );
    const grouped = tables.find(table => table.title === 'Grouped SCA result');
    const serverResults = tables.find(
      table => table.title === 'Selected server results (1)',
    );
    const policyResults = tables.find(
      table => table.title === 'Grouped by policy (1)',
    );
    const controls = tables.find(table => table.title === 'Controls (3)');

    expect(assessmentScope.items[0]).toEqual({
      selected: 1,
      withData: 1,
      verified: 1,
      policies: 1,
    });
    expect(controlOutcome.items[0]).toEqual({
      controls: 3,
      passed: 1,
      failed: 1,
      notApplicable: 1,
      score: '50%',
    });
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage status: all selected servers are verified against their latest indexed SCA scan summary.',
      style: 'standard',
    });

    expect(grouped.items[0]).toEqual({
      selected: 1,
      withData: 1,
      verified: 1,
      coverageIssues: 0,
      controls: 3,
      passed: 1,
      failed: 1,
      notApplicable: 1,
      score: '50%',
    });
    expect(serverResults.items[0]).toEqual(
      expect.objectContaining({
        id: '003',
        name: 'server-003',
        score: '50%',
        passed: 1,
        failed: 1,
        notApplicable: 1,
        controls: 3,
        sca: 'Complete (1 policy)',
      }),
    );
    expect(policyResults.items[0]).toEqual(
      expect.objectContaining({
        policy,
        servers: 1,
        controls: 3,
        passed: 1,
        failed: 1,
        notApplicable: 1,
        coverage: '1/1 complete',
        score: '50%',
      }),
    );

    expect(controls).toBeDefined();
    expect(controls.widths).toEqual([42, 72, '*', 220]);
    expect(controls.fontSize).toBe(7);
    expect(controls.maxTextLength).toBe(38);
    expect(controls.items[0]).toEqual({
      id: '1',
      result: 'Failed',
      title: 'Control 1',
      compliance: 'cis: 1.1.1\npci_dss_v4: 2.2.1, 2.2.2',
    });
    expect(controls.items[1].result).toBe('Not applicable');
    expect(controls.items[2].result).toBe('Passed');

    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage: Complete (3/3 checks) | Score: 50% | Passed: 1 | Failed: 1 | Not applicable: 1',
      style: 'standard',
    });
  });

  it('creates one verified section for every selected server from indexed streams', async () => {
    const linux = 'CIS Linux';
    const windows = 'CIS Windows';
    const { context, search } = buildContext(
      [inventoryBucket('003'), inventoryBucket('004')],
      [
        checkBucket('003', linux, '1', 'passed'),
        checkBucket('004', windows, '2', 'failed'),
      ],
      [
        summaryBucket('003', linux, 1, 1, 0, 0),
        summaryBucket('004', windows, 1, 0, 1, 0),
      ],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003', '004', '003'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    expect(search).toHaveBeenCalledTimes(4);

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const serverResults = tables.find(
      table => table.title === 'Selected server results (2)',
    );
    const controls = tables.filter(table => table.title === 'Controls (1)');

    expect(serverResults.items).toEqual([
      expect.objectContaining({
        id: '003',
        name: 'server-003',
        score: '100%',
        controls: 1,
        sca: 'Complete (1 policy)',
      }),
      expect.objectContaining({
        id: '004',
        name: 'server-004',
        score: '0%',
        controls: 1,
        sca: 'Complete (1 policy)',
      }),
    ]);
    expect(controls).toHaveLength(2);

    expect(printer.addContentWithNewLine).toHaveBeenCalledWith(
      expect.objectContaining({
        text: 'Server server-003 (003)',
        style: 'h2',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith(
      expect.objectContaining({
        text: 'Server server-004 (004)',
        style: 'h2',
      }),
    );
    expect(printer.addContent).toHaveBeenCalledWith({
      text: '',
      pageBreak: 'before',
      pageOrientation: 'landscape',
    });
  });

  it('withholds scores when indexed history has fewer checks than the latest scan summary', async () => {
    const policy = 'CIS Linux';
    const { context } = buildContext(
      [inventoryBucket('003')],
      [checkBucket('003', policy, '1', 'passed')],
      [summaryBucket('003', policy, 2, 1, 1, 0)],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const grouped = tables.find(table => table.title === 'Grouped SCA result');
    const serverResults = tables.find(
      table => table.title === 'Selected server results (1)',
    );
    const policyResults = tables.find(
      table => table.title === 'Grouped by policy (1)',
    );

    expect(grouped.items[0]).toEqual(
      expect.objectContaining({
        verified: 0,
        coverageIssues: 1,
        score: '-',
      }),
    );
    expect(serverResults.items[0]).toEqual(
      expect.objectContaining({
        score: '-',
        sca: 'Incomplete history (1 policy)',
      }),
    );
    expect(policyResults.items[0]).toEqual(
      expect.objectContaining({
        coverage: '0/1 complete',
        score: '-',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage: Incomplete (1/2 checks) | Passed: 1 | Failed: 0 | Not applicable: 0',
      style: 'standard',
    });
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage status: 1 selected server have incomplete, unverified or missing indexed SCA coverage. Detailed scores are withheld where coverage is not complete.',
      style: 'standard',
    });

  });

  it('withholds scores when result distribution disagrees with the latest scan summary', async () => {
    const policy = 'CIS Linux';
    const { context } = buildContext(
      [inventoryBucket('003')],
      [
        checkBucket('003', policy, '1', 'passed'),
        checkBucket('003', policy, '2', 'passed'),
      ],
      [summaryBucket('003', policy, 2, 1, 1, 0)],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    const serverResults = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .find(table => table.title === 'Selected server results (1)');

    expect(serverResults.items[0]).toEqual(
      expect.objectContaining({
        controls: 2,
        score: '-',
        sca: 'Incomplete history (1 policy)',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage: Incomplete (2/2 checks) | Passed: 2 | Failed: 0 | Not applicable: 0',
      style: 'standard',
    });
  });

  it('marks reconstructed checks unverified when no indexed scan summary exists', async () => {
    const policy = 'CIS Linux';
    const { context } = buildContext(
      [inventoryBucket('003')],
      [checkBucket('003', policy, '1', 'passed')],
      [],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    const serverResults = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .find(table => table.title === 'Selected server results (1)');

    expect(serverResults.items[0]).toEqual(
      expect.objectContaining({
        score: '-',
        sca: 'Unverified (1 policy)',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Coverage: Unverified (no indexed scan summary) | Passed: 1 | Failed: 0 | Not applicable: 0',
      style: 'standard',
    });
  });

  it('keeps selected servers with no indexed SCA data visible in the report', async () => {
    const policy = 'CIS Linux';
    const { context } = buildContext(
      [inventoryBucket('003')],
      [checkBucket('003', policy, '1', 'passed')],
      [summaryBucket('003', policy, 1, 1, 0, 0)],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003', '004'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    const serverResults = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .find(table => table.title === 'Selected server results (2)');

    expect(serverResults.items[1]).toEqual(
      expect.objectContaining({
        id: '004',
        score: '-',
        controls: 0,
        sca: 'No indexed SCA data',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'No indexed SCA controls were found for this server.',
      style: 'standard',
    });
  });
});
