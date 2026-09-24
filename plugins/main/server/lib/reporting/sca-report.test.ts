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

const checkBucket = (
  agentId: string,
  policy: string,
  checkId: string,
  result: string,
  compliance: any = {},
) => ({
  key: {
    agent_id: agentId,
    policy_id: policy.toLowerCase().replace(/\s+/g, '_'),
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
                policy_id: policy.toLowerCase().replace(/\s+/g, '_'),
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

const buildContext = (inventoryBuckets: any[], checkBuckets: any[]) => {
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
  it('renders current indexed controls with constrained landscape columns', async () => {
    const { context, search } = buildContext(
      [inventoryBucket('003')],
      [
        checkBucket('003', 'CIS Linux benchmark', '1', 'failed', {
          cis: '1.1.1',
          pci_dss_v4: { 0: '2.2.1,2.2.2' },
        }),
        checkBucket('003', 'CIS Linux benchmark', '2', 'not applicable'),
        checkBucket('003', 'CIS Linux benchmark', '3', 'passed'),
      ],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      '003',
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    expect(search).toHaveBeenCalledTimes(2);
    expect(printer.addContent).toHaveBeenCalledWith(
      expect.objectContaining({
        text: 'Security configuration assessment controls',
        pageBreak: 'before',
        pageOrientation: 'landscape',
      }),
    );

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const controls = tables.find(table => table.title === 'Controls (3)');

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
      text: 'Score: 50% | Passed: 1 | Failed: 1 | Not applicable: 1',
      style: 'standard',
    });
  });

  it('creates one section for every selected server from a single indexed stream', async () => {
    const { context, search } = buildContext(
      [inventoryBucket('003'), inventoryBucket('004')],
      [
        checkBucket('003', 'CIS Linux', '1', 'passed'),
        checkBucket('004', 'CIS Windows', '2', 'failed'),
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

    expect(search).toHaveBeenCalledTimes(2);

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const inventory = tables.find(
      table => table.title === 'Selected servers (2)',
    );
    const controls = tables.filter(table => table.title === 'Controls (1)');

    expect(inventory.items).toEqual([
      expect.objectContaining({
        id: '003',
        name: 'server-003',
        sca: 'Available',
      }),
      expect.objectContaining({
        id: '004',
        name: 'server-004',
        sca: 'Available',
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

  it('keeps selected servers with no indexed SCA controls visible in the report', async () => {
    const { context } = buildContext(
      [inventoryBucket('003')],
      [checkBucket('003', 'CIS Linux', '1', 'passed')],
    );
    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003', '004'],
      'wazuh-alerts-*',
      { bool: { must: [], filter: [] } },
    );

    const inventory = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .find(table => table.title === 'Selected servers (2)');

    expect(inventory.items[1]).toEqual(
      expect.objectContaining({
        id: '004',
        sca: 'No indexed SCA data',
      }),
    );
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'No indexed SCA controls were found for this server.',
      style: 'standard',
    });
  });
});
