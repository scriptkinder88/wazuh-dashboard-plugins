import { WazuhReportingCtrl } from './wazuh-reporting';
import { addScaChecksToReport } from '../lib/reporting/sca-report';

jest.mock('../lib/reporting/sca-report', () => {
  const actual = jest.requireActual('../lib/reporting/sca-report');
  return { addScaChecksToReport: jest.fn(actual.addScaChecksToReport) };
});

const createResponse = () => ({
  ok: jest.fn(options => ({ status: 200, ...options })),
  badRequest: jest.fn(options => ({ status: 400, ...options })),
  custom: jest.fn(options => ({ status: options.statusCode, ...options })),
});

const createContext = (search: jest.Mock) => ({
  wazuh: {
    logger: { debug: jest.fn(), info: jest.fn(), error: jest.fn() },
  },
  core: { opensearch: { client: { asCurrentUser: { search } } } },
});

describe('WazuhReportingCtrl.createScaReport', () => {
  beforeEach(() => jest.clearAllMocks());

  it('responds with the PDF file', async () => {
    const search = jest.fn().mockResolvedValue({ body: { aggregations: {} } });
    const response = createResponse();

    const result: any = await new WazuhReportingCtrl().createScaReport(
      createContext(search) as any,
      { body: { agents: ['001', '001', '002'], details: true } } as any,
      response as any,
    );

    expect(result.status).toBe(200);
    expect(result.headers['content-type']).toBe('application/pdf');
    expect(result.headers['content-disposition']).toMatch(
      /^attachment; filename="wazuh-sca-[0-9]+\.pdf"$/,
    );
    expect(Buffer.isBuffer(result.body)).toBe(true);
    expect(result.body.subarray(0, 5).toString()).toBe('%PDF-');
    expect(addScaChecksToReport).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      ['001', '002'],
      { details: true },
    );
    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({ index: 'wazuh-states-sca*' }),
    );
  });

  it('rejects an empty agent list', async () => {
    const search = jest.fn();
    const response = createResponse();

    const result: any = await new WazuhReportingCtrl().createScaReport(
      createContext(search) as any,
      { body: { agents: [''] } } as any,
      response as any,
    );

    expect(result.status).toBe(400);
    expect(result.body.message).toBe(
      'Select at least one server for the SCA report.',
    );
    expect(search).not.toHaveBeenCalled();
  });

  it.each`
    indexerStatusCode | statusCode
    ${403}            | ${403}
    ${404}            | ${404}
    ${503}            | ${500}
    ${undefined}      | ${500}
  `(
    'returns the error message with status $statusCode (indexer $indexerStatusCode)',
    async ({ indexerStatusCode, statusCode }) => {
      const search = jest.fn().mockRejectedValue(
        Object.assign(new Error('search failed'), {
          meta: indexerStatusCode
            ? {
                statusCode: indexerStatusCode,
                body: { error: { reason: 'no such index' } },
              }
            : undefined,
        }),
      );
      const response = createResponse();

      const result: any = await new WazuhReportingCtrl().createScaReport(
        createContext(search) as any,
        { body: { agents: ['001'] } } as any,
        response as any,
      );

      expect(result.status).toBe(statusCode);
      expect(result.body.message).toBe(
        `5029 - Reporting was aborted (${
          indexerStatusCode ? 'no such index' : 'search failed'
        })`,
      );
    },
  );
});
