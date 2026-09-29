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
  scanId: number = 42,
) => ({
  key: {
    agent_id: agentId,
    policy,
    scan_id: scanId,
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
                scan_id: scanId,
                check: {
                  id: checkId,
                  title: `Control ${checkId}`,
                  result,
                  rationale: `Rationale ${checkId}`,
                  remediation: `Remediation ${checkId}`,
                  description: `Description ${checkId}`,
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
        checkBucket('003', policy, '999', 'failed', {}, 41),
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
      { details: true },
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
    const groupedOverview = printer.addContent.mock.calls
      .map(call => call[0])
      .find(content => content?.id === 'sca-grouped-overview');
    const serverResults = tables.find(
      table => table.title === 'Selected server results (1)',
    );
    const policyResults = tables.find(
      table => table.title === 'Grouped by policy (1)',
    );
    const controls = tables.find(table => table.title === 'Controls (3)');

    const executiveRows = printer.addContent.mock.calls
      .map(call => call[0])
      .filter(
        content =>
          Array.isArray(content?.columns) &&
          content?.id !== 'sca-grouped-overview',
      );

    expect(executiveRows).toHaveLength(2);
    expect(
      executiveRows[0].columns.map(
        column => column.table.body[0][0].stack[0].text,
      ),
    ).toEqual(['1', '1', '1', '1']);
    expect(
      executiveRows[1].columns.map(
        column => column.table.body[0][0].stack[0].text,
      ),
    ).toEqual(['3', '1', '1', '1', '50%']);
    expect(printer.addContent).toHaveBeenCalledWith(
      expect.objectContaining({
        table: expect.objectContaining({
          body: [
            [
              expect.objectContaining({
                text: 'Coverage verified: all selected servers match their latest indexed SCA scan summary.',
              }),
            ],
          ],
        }),
      }),
    );

    expect(groupedOverview).toBeDefined();
    expect(
      groupedOverview.columns[0].table.body[1].map(cell => cell.text),
    ).toEqual(['1', '1', '1', '0', '3', '1', '1', '1', '50%']);
    expect(groupedOverview.columns[1].stack[1].svg).toContain('#00A69B');
    expect(groupedOverview.columns[1].stack[1].svg).toContain('#FF645C');
    expect(groupedOverview.columns[1].stack[1].svg).toContain('#5C6773');
    expect(groupedOverview.columns[1].stack[2].columns[0].text).toEqual([
      { text: '● ', color: '#00A69B' },
      'Passed (1)',
    ]);
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
    expect(controls.columns.map(column => column.id)).toEqual([
      'reference',
      'result',
      'title',
      'rationale',
      'remediation',
      'description',
      'compliance',
    ]);
    expect(controls.widths).toEqual([32, 44, 110, 108, 142, 152, 142]);
    const effectiveTableWidth =
      controls.widths.reduce((total, width) => total + width, 0) +
      controls.columns.length * controls.cellPadding * 2;
    expect(effectiveTableWidth).toBeLessThanOrEqual(761);
    expect(controls.fontSize).toBe(6.5);
    expect(controls.maxTextLength).toBe(34);
    expect(controls.margin).toBeUndefined();
    expect(controls.cellPadding).toBe(1);
    expect(controls.columns[controls.columns.length - 1].id).toBe('compliance');
    expect(controls.items[0]).toEqual({
      reference: '1.1.1',
      result: 'Failed',
      title: 'Control 1',
      rationale: 'Rationale 1',
      remediation: 'Remediation 1',
      description: 'Description 1',
      compliance: 'cis: 1.1.1\npci_dss_v4: 2.2.1, 2.2.2',
    });
    expect(controls.items[1].result).toBe('Not applicable');
    expect(controls.items[2].result).toBe('Passed');
    expect(controls.items.map(item => item.reference)).not.toContain('ID 999');

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
      { details: true },
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
      { details: true },
    );

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const groupedOverview = printer.addContent.mock.calls
      .map(call => call[0])
      .find(content => content?.id === 'sca-grouped-overview');
    const serverResults = tables.find(
      table => table.title === 'Selected server results (1)',
    );
    const policyResults = tables.find(
      table => table.title === 'Grouped by policy (1)',
    );

    expect(groupedOverview).toBeDefined();
    expect(
      groupedOverview.columns[0].table.body[1].map(cell => cell.text),
    ).toEqual(['1', '1', '0', '1', '1', '1', '0', '0', '-']);
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
    expect(printer.addContent).toHaveBeenCalledWith(
      expect.objectContaining({
        table: expect.objectContaining({
          body: [
            [
              expect.objectContaining({
                text: 'Coverage requires attention: 1 selected server has incomplete, unverified or missing indexed SCA coverage. Scores are withheld wherever coverage is not complete.',
              }),
            ],
          ],
        }),
      }),
    );
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
      { details: true },
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
      { details: true },
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
      { details: true },
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

  it('omits the per-server detail by default and groups results by family', async () => {
    const policy = 'CIS Linux';
    const { context, search } = buildContext(
      [inventoryBucket('003'), inventoryBucket('004')],
      [
        checkBucket('003', policy, '1', 'failed', { cis: '1.10' }),
        checkBucket('003', policy, '2', 'passed', { cis: '1.2' }),
        checkBucket('003', policy, '3', 'failed', { cis: '18.9.1' }),
        checkBucket('003', policy, '4', 'failed'),
        checkBucket('004', policy, '1', 'failed', { cis: '1.10' }),
        checkBucket('004', policy, '2', 'failed', { cis: '1.2' }),
        checkBucket('004', policy, '3', 'passed', { cis: '18.9.1' }),
        checkBucket('004', policy, '4', 'passed'),
      ],
      [
        summaryBucket('003', policy, 4, 1, 3, 0),
        summaryBucket('004', policy, 4, 2, 2, 0),
      ],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003', '004'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    // Inventory, summaries and a single pass over the checks.
    expect(search).toHaveBeenCalledTimes(3);
    const texts = [
      ...printer.addContent.mock.calls,
      ...printer.addContentWithNewLine.mock.calls,
    ].map(call => call[0]?.text);
    expect(texts).not.toContain('Detailed results by selected server');
    expect(texts).toContain('Results by benchmark family');

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    expect(tables.some(table => /^Controls /.test(table.title))).toBe(false);

    const families = tables.find(
      table => table.title === 'Results by family (3)',
    );
    expect(families.items).toEqual([
      {
        family: 'Family 1',
        controls: 4,
        passed: 1,
        failed: 3,
        notApplicable: 0,
        passRate: '25%',
      },
      {
        family: 'Family 18',
        controls: 2,
        passed: 1,
        failed: 1,
        notApplicable: 0,
        passRate: '50%',
      },
      {
        family: 'Not mapped to a family',
        controls: 2,
        passed: 1,
        failed: 1,
        notApplicable: 0,
        passRate: '50%',
      },
    ]);

    const familyOne = tables.find(table => table.title === 'Family 1 (2)');
    expect(familyOne.items).toEqual([
      {
        reference: '1.2',
        title: 'Control 2',
        affected: 1,
        servers: 'server-004 (004)',
      },
      {
        reference: '1.10',
        title: 'Control 1',
        affected: 2,
        servers: 'server-003 (003), server-004 (004)',
      },
    ]);
    expect(
      tables.find(table => table.title === 'Not mapped to a family (1)')
        .items[0].reference,
    ).toBe('ID 4');

    const chart = printer.addContent.mock.calls
      .map(call => call[0])
      .find(content => typeof content?.svg === 'string');
    expect(chart.svg).toContain('Family 18');
    expect(chart.svg).toContain('3/4 failed');
  });

  it('uses CIS-CAT Pro title numbers and withholds partial pass rates', async () => {
    const policy = 'CIS-CAT Pro tailored';
    const imported = (checkId: string, title: string, result: string) => {
      const bucket = checkBucket('003', policy, checkId, result, {
        cis: '9.9',
      });
      bucket.latest.hits.hits[0]._source.data.sca.check.title = title;
      return bucket;
    };
    const { context } = buildContext(
      [inventoryBucket('003')],
      [
        imported('5001', '1.1.1 Ensure cramfs is disabled', 'failed'),
        imported('5002', '2.2.5 Ensure a service is disabled', 'passed'),
      ],
      [summaryBucket('003', policy, 3, 1, 2, 0)],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      '003',
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
      { details: true },
    );

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    expect(
      tables.find(table => table.title === 'Results by family (2)').items,
    ).toEqual([
      expect.objectContaining({ family: 'Family 1', passRate: '-' }),
      expect.objectContaining({ family: 'Family 2', passRate: '-' }),
    ]);
    expect(
      tables.find(table => table.title === 'Family 1 (1)').items[0],
    ).toEqual(
      expect.objectContaining({
        reference: '1.1.1',
        title: 'Ensure cramfs is disabled',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith(
      expect.objectContaining({
        text: expect.stringContaining('Pass rates are withheld'),
      }),
    );
    const controls = tables.find(table => table.title === 'Controls (2)');
    expect(controls.items.map(item => [item.reference, item.title])).toEqual([
      ['1.1.1', 'Ensure cramfs is disabled'],
      ['2.2.5', 'Ensure a service is disabled'],
    ]);
  });
});
