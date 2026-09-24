import { addScaChecksToReport } from './sca-report';

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
      async (_method, endpoint, { params: { offset } }) => {
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

    const printer = {
      logger: {
        debug: jest.fn(),
      },
      addContentWithNewLine: jest.fn().mockReturnThis(),
      addSimpleTable: jest.fn().mockReturnThis(),
    };

    await addScaChecksToReport(context, printer as any, '003', 'default');

    expect(request).toHaveBeenCalledTimes(3);
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
});
