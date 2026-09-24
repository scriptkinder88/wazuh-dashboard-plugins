import { addScaChecksToReport } from './sca-report';

const createPrinter = () => ({
  logger: {
    debug: jest.fn(),
  },
  addContent: jest.fn().mockReturnThis(),
  addContentWithNewLine: jest.fn().mockReturnThis(),
  addSimpleTable: jest.fn().mockReturnThis(),
});

describe('SCA report controls', () => {
  it('adds every control with its result and compliance mapping', async () => {
    const checks = Array.from({ length: 101 }, (_, index) => ({
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
      async (_method, endpoint, { params: { offset = 0 } }) => {
        if (endpoint === '/agents') {
          return {
            data: {
              data: {
                affected_items: [
                  {
                    id: '003',
                    name: 'server-003',
                    status: 'active',
                    group: ['servers'],
                    os: { name: 'Windows Server', version: '2022' },
                  },
                ],
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
                    name: 'CIS Windows benchmark',
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
                affected_items: checks.slice(offset, offset + 100),
                total_affected_items: checks.length,
              },
            },
          };
        }

        throw new Error(`Unexpected endpoint: ${endpoint}`);
      },
    );

    const context = {
      wazuh: {
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
    expect(printer.addSimpleTable).toHaveBeenCalledTimes(1);

    const table = printer.addSimpleTable.mock.calls[0][0];

    expect(table.title).toBe('Controls (101)');
    expect(table.items).toHaveLength(101);
    expect(table.items[0]).toEqual({
      id: '1',
      result: 'Failed',
      title: 'Control 1',
      compliance: 'cis: 1.1.1\npci_dss: 2.2.1',
    });
    expect(table.items[1].result).toBe('Not applicable');
    expect(table.items[2].result).toBe('Passed');
  });

  it('creates an independent SCA section for every selected server', async () => {
    const request = jest.fn(async (_method, endpoint) => {
      if (endpoint === '/agents') {
        const agentId = request.mock.calls[request.mock.calls.length - 1][2]
          .params.q.split('=')[1];

        return {
          data: {
            data: {
              affected_items: [
                {
                  id: agentId,
                  name: `server-${agentId}`,
                  status: 'active',
                  group: ['servers'],
                  os: { name: 'Linux', version: '12' },
                },
              ],
              total_affected_items: 1,
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

    expect(printer.addSimpleTable).toHaveBeenCalledTimes(2);
    expect(printer.addSimpleTable.mock.calls[0][0].items[0]).toEqual(
      expect.objectContaining({
        result: 'Passed',
        title: 'Control for 003',
      }),
    );
    expect(printer.addSimpleTable.mock.calls[1][0].items[0]).toEqual(
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
    });
  });
});
