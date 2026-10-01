/* eslint-disable camelcase -- OpenSearch DSL and responses */
import { ReportPrinter } from './printer';
import { addScaChecksToReport } from './sca-report';

const logger = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

interface StateFixture {
  agent: string;
  name?: string;
  policy?: string;
  policyName?: string;
  checkId: string;
  title: string;
  result: string;
  modifiedAt?: string;
}

const toDocument = ({
  agent,
  name = `server-${agent}`,
  policy = 'cis_rhel9_linux',
  policyName = 'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0',
  checkId,
  title,
  result,
  modifiedAt = '2026-09-30T10:00:00.000Z',
}: StateFixture) => ({
  wazuh: { agent: { id: agent, name, host: { ip: `10.0.0.${agent}` } } },
  policy: { id: policy, name: policyName },
  check: {
    id: checkId,
    name: title,
    result,
    rationale: `Rationale ${checkId}`,
    remediation: `Remediation ${checkId}`,
    description: `Description ${checkId}`,
    compliance: { pci_dss: ['2.2'], nist_800_53: ['CM-6'] },
  },
  state: { modified_at: modifiedAt },
});

const compareKeys = (a: string[], b: string[]) => {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
};

/**
 * Minimal in-memory indexer answering the aggregations of
 * sca-states-request.ts over a list of states documents.
 */
const createFakeIndexer = (
  documents: any[],
  { summaryOverrides = {} }: { summaryOverrides?: Record<string, any> } = {},
) => {
  const answer = ({ body }) => {
    const agents: string[] = body.query.bool.filter[0].terms['wazuh.agent.id'];
    const matched = documents.filter(doc =>
      agents.includes(doc.wazuh.agent.id),
    );
    const latestFirst = (docs: any[]) =>
      [...docs].sort((a, b) =>
        b.state.modified_at.localeCompare(a.state.modified_at),
      );

    const composite = (name: string, keyOf: (doc: any) => string[]) => {
      const { size, after, sources } = body.aggs[name].composite;
      const names = sources.map(source => Object.keys(source)[0]);
      const groups = new Map<string, any[]>();
      for (const doc of matched) {
        const id = JSON.stringify(keyOf(doc));
        groups.set(id, [...(groups.get(id) || []), doc]);
      }
      const keys = Array.from(groups.keys())
        .map(id => JSON.parse(id))
        .sort(compareKeys)
        .filter(
          key =>
            !after ||
            compareKeys(
              key,
              names.map(keyName => after[keyName]),
            ) > 0,
        )
        .slice(0, size);
      const buckets = keys.map(key => ({
        key: Object.fromEntries(names.map((keyName, i) => [keyName, key[i]])),
        docs: groups.get(JSON.stringify(key)),
      }));
      return {
        after_key: buckets.length ? buckets[buckets.length - 1].key : undefined,
        buckets,
      };
    };

    if (body.aggs.scaAgents) {
      const byAgent = new Map<string, any[]>();
      for (const doc of matched) {
        byAgent.set(doc.wazuh.agent.id, [
          ...(byAgent.get(doc.wazuh.agent.id) || []),
          doc,
        ]);
      }
      return {
        body: {
          aggregations: {
            scaAgents: {
              buckets: Array.from(byAgent.entries()).map(([key, docs]) => ({
                key,
                latest: { hits: { hits: [{ _source: latestFirst(docs)[0] }] } },
              })),
            },
          },
        },
      };
    }

    if (body.aggs.scaPolicySummaries) {
      const { after_key, buckets } = composite('scaPolicySummaries', doc => [
        doc.wazuh.agent.id,
        doc.policy.id,
      ]);
      return {
        body: {
          aggregations: {
            scaPolicySummaries: {
              after_key,
              buckets: buckets.map(({ key, docs }) => {
                const results = new Map<string, number>();
                for (const doc of docs) {
                  results.set(
                    doc.check.result,
                    (results.get(doc.check.result) || 0) + 1,
                  );
                }
                return {
                  key,
                  policyName: { buckets: [{ key: docs[0].policy.name }] },
                  checks: {
                    value: new Set(docs.map(doc => doc.check.id)).size,
                  },
                  results: {
                    buckets: Array.from(results.entries()).map(
                      ([result, count]) => ({ key: result, doc_count: count }),
                    ),
                  },
                  lastModified: {
                    value_as_string: latestFirst(docs)[0].state.modified_at,
                  },
                  ...(summaryOverrides[`${key.agentId}::${key.policyId}`] ||
                    {}),
                };
              }),
            },
          },
        },
      };
    }

    const { after_key, buckets } = composite('scaChecks', doc => [
      doc.wazuh.agent.id,
      doc.policy.id,
      doc.check.id,
    ]);
    return {
      body: {
        aggregations: {
          scaChecks: {
            after_key,
            buckets: buckets.map(({ key, docs }) => ({
              key,
              latest: { hits: { hits: [{ _source: latestFirst(docs)[0] }] } },
            })),
          },
        },
      },
    };
  };
  const search = jest.fn(params => Promise.resolve(answer(params)));

  return {
    search,
    context: {
      core: { opensearch: { client: { asCurrentUser: { search } } } },
    },
  };
};

// Collects every text of the report, including table cells and SVG labels.
const collectTexts = (node: any, texts: string[] = []): string[] => {
  if (Array.isArray(node)) {
    node.forEach(child => collectTexts(child, texts));
  } else if (node && typeof node === 'object') {
    if (typeof node.text === 'string') {
      texts.push(node.text);
    }
    if (typeof node.svg === 'string') {
      texts.push(node.svg);
    }
    Object.entries(node).forEach(([key, value]) => {
      if (key !== 'text' && key !== 'svg') {
        collectTexts(value, texts);
      }
    });
  }
  return texts;
};

const findTableRows = (printer: ReportPrinter, title: string) => {
  const content = printer.getContent();
  const index = content.findIndex(node => node?.text === title);
  if (index < 0) {
    return undefined;
  }
  const table = content.slice(index).find(node => node?.table);
  return table.table.body.map(row => row.map(cell => cell.text));
};

const FIXTURES: StateFixture[] = [
  {
    agent: '001',
    checkId: '35500',
    title: '1.1.1 Ensure cramfs is disabled',
    result: 'Failed',
  },
  {
    agent: '001',
    checkId: '35501',
    title: '1.1.2 Ensure squashfs is disabled',
    result: 'Passed',
  },
  {
    agent: '001',
    checkId: '35600',
    title: '5.2.1 Ensure permissions on sshd_config are set',
    result: 'failed',
  },
  {
    agent: '001',
    checkId: '35700',
    title: 'Ensure the web server is hardened',
    result: 'Not applicable',
  },
  {
    agent: '002',
    checkId: '35500',
    title: '1.1.1 Ensure cramfs is disabled',
    result: 'Failed',
  },
  {
    agent: '002',
    checkId: '35501',
    title: '1.1.2 Ensure squashfs is disabled',
    result: 'Passed',
  },
];

describe('SCA report from the SCA states index', () => {
  beforeEach(() => jest.clearAllMocks());

  it('adds the executive summary, families and failed controls', async () => {
    const { context, search } = createFakeIndexer(FIXTURES.map(toDocument));
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['001', '002', '003']);

    expect(search).toHaveBeenCalled();
    for (const [{ index, body }] of search.mock.calls) {
      expect(index).toBe('wazuh-states-sca*');
      expect(body.query.bool.filter[0]).toEqual({
        terms: { 'wazuh.agent.id': ['001', '002', '003'] },
      });
    }

    const texts = collectTexts(printer.getContent());
    expect(texts).toContain('Executive summary');
    expect(texts).toContain('Results by benchmark family');
    expect(texts).not.toContain('Detailed results by selected server');
    // 003 has no SCA data, so coverage needs attention.
    expect(texts.join('\n')).toContain(
      'Coverage requires attention: 1 selected server has no, inconsistent',
    );

    expect(findTableRows(printer, 'Selected server results (3)')).toEqual([
      [
        'ID',
        'Server',
        'Score',
        'Passed',
        'Failed',
        'N/A',
        'Controls',
        'SCA data',
      ],
      ['001', 'server-001', '33%', '1', '2', '1', '4', 'Complete (1 policy)'],
      ['002', 'server-002', '50%', '1', '1', '0', '2', 'Complete (1 policy)'],
      ['003', 'Unknown server', '-', '0', '0', '0', '0', 'No SCA data'],
    ]);

    expect(findTableRows(printer, 'Results by family (3)')).toEqual([
      ['Family', 'Controls', 'Passed', 'Failed', 'N/A', 'Pass rate'],
      ['Family 1 - Initial Setup', '4', '2', '2', '0', '50%'],
      [
        // Long cells are wrapped.
        'Family 5 - Access, Authentication and\nAuthorization',
        '1',
        '0',
        '1',
        '0',
        '0%',
      ],
      ['Not mapped to a family', '1', '0', '0', '1', '-'],
    ]);

    expect(texts).toContain('Failed controls by family (2)');
    expect(findTableRows(printer, 'Family 1 - Initial Setup (1)')).toEqual([
      ['CIS', 'Control', 'Servers', 'Affected servers'],
      [
        '1.1.1',
        'Ensure cramfs is disabled',
        '2',
        'server-001 (001), server-002 (002)',
      ],
    ]);
    expect(
      findTableRows(
        printer,
        'Family 5 - Access, Authentication and Authorization (1)',
      ),
    ).toEqual([
      ['CIS', 'Control', 'Servers', 'Affected servers'],
      [
        '5.2.1',
        'Ensure permissions on sshd_config are set',
        '1',
        'server-001 (001)',
      ],
    ]);
  });

  it('shows the overall score only when every server is verified', async () => {
    const { context } = createFakeIndexer(FIXTURES.map(toDocument));
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['001', '002']);

    const texts = collectTexts(printer.getContent());
    expect(texts.join('\n')).toContain('Coverage verified');
    // 2 passed of 5 passed or failed controls.
    expect(texts).toContain('40%');
  });

  it('withholds the scores when the read checks do not match the index totals', async () => {
    const { context } = createFakeIndexer(FIXTURES.map(toDocument), {
      summaryOverrides: { '002::cis_rhel9_linux': { checks: { value: 3 } } },
    });
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['002'], { details: true });

    expect(findTableRows(printer, 'Selected server results (1)')[1]).toEqual([
      '002',
      'server-002',
      '-',
      '1',
      '1',
      '0',
      '2',
      'Inconsistent (1 policy)',
    ]);
    const texts = collectTexts(printer.getContent());
    expect(texts.join('\n')).toContain(
      'Coverage: Inconsistent (2/3 checks) | Passed: 1 | Failed: 1',
    );
  });

  it('adds the per-server details on request, in CIS order', async () => {
    const { context } = createFakeIndexer(
      [
        ...FIXTURES,
        {
          agent: '001',
          checkId: '35499',
          title: '1.10 Ensure something late',
          result: 'Passed',
        },
      ].map(toDocument),
    );
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['001', '004'], {
      details: true,
    });

    const texts = collectTexts(printer.getContent());
    expect(texts).toContain('Detailed results by selected server');
    expect(texts).toContain('Server server-001 (001)');
    expect(texts).toContain('Server Unknown server (004)');
    expect(texts).toContain('No SCA checks were found for this server.');

    const rows = findTableRows(printer, 'Controls (5)');
    expect(rows[0]).toEqual([
      'CIS',
      'Result',
      'Control',
      'Rationale',
      'Remediation',
      'Description',
      'Compliance',
    ]);
    expect(rows.slice(1).map(row => [row[0], row[1]])).toEqual([
      ['1.1.1', 'Failed'],
      ['1.1.2', 'Passed'],
      ['1.10', 'Passed'],
      ['5.2.1', 'Failed'],
      ['ID 35700', 'Not applicable'],
    ]);
    expect(rows[1][6]).toBe('pci_dss: 2.2\nnist_800_53: CM-6');
  });

  it('pages through more checks than the page size', async () => {
    const documents = Array.from({ length: 1205 }, (_, index) =>
      toDocument({
        agent: '001',
        checkId: String(10000 + index),
        title: `${(index % 6) + 1}.1 Ensure control ${index}`,
        result: index % 2 ? 'Passed' : 'Failed',
      }),
    );
    const { context, search } = createFakeIndexer(documents);
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['001']);

    const checkCalls = search.mock.calls.filter(
      ([{ body }]) => body.aggs.scaChecks,
    );
    // A full page, a partial page and the empty last page.
    expect(checkCalls).toHaveLength(3);
    expect(findTableRows(printer, 'Selected server results (1)')[1]).toEqual([
      '001',
      'server-001',
      '50%',
      '602',
      '603',
      '0',
      '1205',
      'Complete (1 policy)',
    ]);
  });

  it('renders a PDF document', async () => {
    const { context } = createFakeIndexer(FIXTURES.map(toDocument));
    const printer = new ReportPrinter(logger as any);

    await addScaChecksToReport(context, printer, ['001', '002'], {
      details: true,
    });
    const pdf = await printer.printToBuffer();

    expect(Buffer.isBuffer(pdf)).toBe(true);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
  });
});
