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

const buildAgent = (id: string) => ({
  id,
  name: `server-${id}`,
  status: 'active',
  group: ['servers'],
  os: { name: 'Linux', version: '12' },
});

describe('SCA report controls', () => {
  it('adds every control with pagination and constrained landscape columns', async () => {
    const checks = Array.from({ length: 501 }, (_, index) => ({
      id: index + 1,
      title: `Control ${index + 1}`,
      result:
        index === 0 ? 'failed' : index === 1 ? 'not applicable' : 'passed',
      compliance:
        index === 0
          ? [
              { key: 'cis', value: '1.1.1' },
              { key: 'pci_dss', value: '2.2.1' },
            ]
          : [],
    }));

    const request = jest.fn(
      async (_method, endpoint, { params: { offset = 0, ...params } }) => {
        if (endpoint === '/agents') {
          return {
            data: {
              data: {
                affected_items: [buildAgent('003')],
                total_affected_items: 1,
              },
            },
          };
        }

        if (endpoint === '/sca/003') {
          return {
            data: {
              data: {
                affected_items: [
                  {
                    policy_id: 'policy_1',
                    name: 'CIS Linux benchmark',
                    score: 78,
                    pass: 80,
                    fail: 20,
                    invalid: 1,
                  },
                ],
                total_affected_items: 1,
              },
            },
          };
        }

        if (endpoint === '/sca/003/checks/policy_1') {
          return {
            data: {
              data: {
                affected_items: checks.slice(offset, offset + 500),
                total_affected_items: checks.length,
              },
            },
          };
        }

        throw new Error(
          `Unexpected endpoint: ${endpoint} with ${JSON.stringify(params)}`,
        );
      },
    );

    const context = {
      wazuh: {
        logger: {
          debug: jest.fn(),
        },
        api: {
          client: {
            asCurrentUser: {
              request,
            },
          },
        },
      },
    };

    const printer = createPrinter();

    await addScaChecksToReport(context, printer as any, '003', 'default');

    expect(request).toHaveBeenCalledTimes(4);
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/agents',
      {
        params: expect.objectContaining({
          agents_list: '003',
          limit: 1,
          select: 'id,name,status,group,os.name,os.version',
        }),
      },
      { apiHostID: 'default' },
    );
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/sca/003',
      {
        params: expect.objectContaining({
          limit: 500,
          select: 'policy_id,name,score,pass,fail,invalid',
        }),
      },
      { apiHostID: 'default' },
    );
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/sca/003/checks/policy_1',
      {
        params: expect.objectContaining({
          limit: 500,
          select: 'id,title,result,compliance.key,compliance.value',
        }),
      },
      { apiHostID: 'default' },
    );

    expect(printer.addContent).toHaveBeenCalledWith(
      expect.objectContaining({
        text: 'Security configuration assessment controls',
        pageBreak: 'before',
        pageOrientation: 'landscape',
      }),
    );

    const controlsTable = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .find(table => table.title === 'Controls (501)');

    expect(controlsTable).toBeDefined();
    expect(controlsTable.items).toHaveLength(501);
    expect(controlsTable.widths).toEqual([42, 72, '*', 220]);
    expect(controlsTable.fontSize).toBe(7);
    expect(controlsTable.maxTextLength).toBe(42);
    expect(controlsTable.items[0]).toEqual({
      id: '1',
      result: 'Failed',
      title: 'Control 1',
      compliance: 'cis: 1.1.1\npci_dss: 2.2.1',
    });
    expect(controlsTable.items[1].result).toBe('Not applicable');
    expect(controlsTable.items[2].result).toBe('Passed');
  });

  it('loads selected server metadata in one batch and creates an independent section per server', async () => {
    const request = jest.fn(async (_method, endpoint, options) => {
      if (endpoint === '/agents') {
        const agentIds = options.params.agents_list.split(',');

        return {
          data: {
            data: {
              affected_items: agentIds.map(buildAgent),
              total_affected_items: agentIds.length,
            },
          },
        };
      }

      const policyMatch = endpoint.match(/^\/sca\/(003|004)$/);
      if (policyMatch) {
        return {
          data: {
            data: {
              affected_items: [
                {
                  policy_id: 'policy_1',
                  name: 'Server benchmark',
                  score: 90,
                  pass: 9,
                  fail: 1,
                  invalid: 0,
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      const checksMatch = endpoint.match(
        /^\/sca\/(003|004)\/checks\/policy_1$/,
      );
      if (checksMatch) {
        const agentId = checksMatch[1];

        return {
          data: {
            data: {
              affected_items: [
                {
                  id: 1,
                  title: `Control for ${agentId}`,
                  result: agentId === '003' ? 'passed' : 'failed',
                  compliance: [],
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      throw new Error(`Unexpected endpoint: ${endpoint}`);
    });

    const context = {
      wazuh: {
        logger: {
          debug: jest.fn(),
        },
        api: {
          client: {
            asCurrentUser: {
              request,
            },
          },
        },
      },
    };

    const printer = createPrinter();

    await addScaChecksToReport(
      context,
      printer as any,
      ['003', '004', '003'],
      'default',
    );

    const agentRequests = request.mock.calls.filter(
      ([, endpoint]) => endpoint === '/agents',
    );
    expect(agentRequests).toHaveLength(1);
    expect(agentRequests[0][2].params.agents_list).toBe('003,004');

    const tables = printer.addSimpleTable.mock.calls.map(call => call[0]);
    const inventory = tables.find(
      table => table.title === 'Selected servers (2)',
    );
    const controls = tables.filter(table => table.title === 'Controls (1)');

    expect(inventory).toBeDefined();
    expect(inventory.items).toEqual([
      expect.objectContaining({ id: '003', name: 'server-003' }),
      expect.objectContaining({ id: '004', name: 'server-004' }),
    ]);
    expect(inventory.widths).toEqual([45, 190, 70, '*']);
    expect(controls).toHaveLength(2);
    expect(controls[0].items[0]).toEqual(
      expect.objectContaining({
        result: 'Passed',
        title: 'Control for 003',
      }),
    );
    expect(controls[1].items[0]).toEqual(
      expect.objectContaining({
        result: 'Failed',
        title: 'Control for 004',
      }),
    );

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

  it('continues when one selected server has unavailable SCA data', async () => {
    const request = jest.fn(async (_method, endpoint, options) => {
      if (endpoint === '/agents') {
        const agentIds = options.params.agents_list.split(',');

        return {
          data: {
            data: {
              affected_items: agentIds.map(buildAgent),
              total_affected_items: agentIds.length,
            },
          },
        };
      }

      if (endpoint === '/sca/003') {
        return {
          data: {
            data: {
              affected_items: [
                {
                  policy_id: 'policy_1',
                  name: 'Server benchmark',
                  score: 100,
                  pass: 1,
                  fail: 0,
                  invalid: 0,
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      if (endpoint === '/sca/003/checks/policy_1') {
        return {
          data: {
            data: {
              affected_items: [
                {
                  id: 1,
                  title: 'Control for 003',
                  result: 'passed',
                  compliance: [],
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      if (endpoint === '/sca/004') {
        throw new Error('SCA database unavailable');
      }

      throw new Error(`Unexpected endpoint: ${endpoint}`);
    });

    const context = {
      wazuh: {
        logger: {
          debug: jest.fn(),
        },
        api: {
          client: {
            asCurrentUser: {
              request,
            },
          },
        },
      },
    };

    const printer = createPrinter();

    await expect(
      addScaChecksToReport(context, printer as any, ['003', '004'], 'default'),
    ).resolves.toBeUndefined();

    const controls = printer.addSimpleTable.mock.calls
      .map(call => call[0])
      .filter(table => table.title === 'Controls (1)');

    expect(controls).toHaveLength(1);
    expect(printer.addContentWithNewLine).toHaveBeenCalledWith({
      text: 'Unable to retrieve SCA policies for this server.',
      style: 'standard',
    });
  });

  it('retries a Wazuh API request after a 429 response', async () => {
    let policyAttempts = 0;

    const request = jest.fn(async (_method, endpoint) => {
      if (endpoint === '/agents') {
        return {
          data: {
            data: {
              affected_items: [buildAgent('003')],
              total_affected_items: 1,
            },
          },
        };
      }

      if (endpoint === '/sca/003') {
        policyAttempts++;

        if (policyAttempts === 1) {
          const error: any = new Error('Request failed with status code 429');
          error.response = { status: 429 };
          throw error;
        }

        return {
          data: {
            data: {
              affected_items: [
                {
                  policy_id: 'policy_1',
                  name: 'Server benchmark',
                  score: 100,
                  pass: 1,
                  fail: 0,
                  invalid: 0,
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      if (endpoint === '/sca/003/checks/policy_1') {
        return {
          data: {
            data: {
              affected_items: [
                {
                  id: 1,
                  title: 'Control',
                  result: 'passed',
                  compliance: [],
                },
              ],
              total_affected_items: 1,
            },
          },
        };
      }

      throw new Error(`Unexpected endpoint: ${endpoint}`);
    });

    const context = {
      wazuh: {
        logger: {
          debug: jest.fn(),
        },
        api: {
          client: {
            asCurrentUser: {
              request,
            },
          },
        },
      },
    };

    const printer = createPrinter();

    await addScaChecksToReport(context, printer as any, '003', 'default');

    expect(policyAttempts).toBe(2);
    expect(context.wazuh.logger.debug).toHaveBeenCalledWith(
      expect.stringContaining('SCA report API rate limited'),
    );
  });
});
