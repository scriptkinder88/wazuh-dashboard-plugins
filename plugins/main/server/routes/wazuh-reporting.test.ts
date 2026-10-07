/** @jest-environment node */
// To launch this file
// yarn test:jest --testEnvironment node --verbose server/routes/wazuh-reporting
import supertest from 'supertest';
import { createMockPlatformServer } from '../mocks/platform-server.mock';
import { WazuhReportingRoutes } from './wazuh-reporting';
import { addScaChecksToReport } from '../lib/reporting/sca-report';

jest.mock('../lib/reporting/sca-report', () => {
  const actual = jest.requireActual('../lib/reporting/sca-report');
  return { addScaChecksToReport: jest.fn(actual.addScaChecksToReport) };
});

const mockSearch = jest.fn();
const logger = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
const context = {
  wazuh: { logger },
  core: {
    opensearch: { client: { asCurrentUser: { search: mockSearch } } },
  },
};
const mockPlatformServer = createMockPlatformServer(context);

beforeAll(async () => {
  await mockPlatformServer.start(router => WazuhReportingRoutes(router));
});

afterAll(async () => {
  await mockPlatformServer.stop();
});

describe('[endpoint] POST /reports/sca', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSearch.mockResolvedValue({ body: { aggregations: {} } });
  });

  it('returns the PDF report as an attachment', async () => {
    const response = await supertest(mockPlatformServer.getServerListener())
      .post('/reports/sca')
      .set('osd-xsrf', 'kibana')
      .send({ agents: ['001', '002'] })
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      })
      .expect(200);

    expect(response.headers['content-type']).toBe('application/pdf');
    expect(response.headers['content-disposition']).toMatch(
      /^attachment; filename="wazuh-sca-[0-9]+\.pdf"$/,
    );
    expect(response.body.subarray(0, 5).toString()).toBe('%PDF-');
    expect(addScaChecksToReport).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      ['001', '002'],
      { details: false },
    );
    expect(mockSearch).toHaveBeenCalledWith(
      expect.objectContaining({ index: 'wazuh-states-sca*' }),
    );
  });

  it('passes the details option', async () => {
    await supertest(mockPlatformServer.getServerListener())
      .post('/reports/sca')
      .set('osd-xsrf', 'kibana')
      .send({ agents: ['001'], details: true })
      .expect(200);

    expect(addScaChecksToReport).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      ['001'],
      { details: true },
    );
  });

  it.each`
    body                                   | title
    ${{}}                                  | ${'no agents'}
    ${{ agents: [] }}                      | ${'an empty agent list'}
    ${{ agents: [''] }}                    | ${'an empty agent ID'}
    ${{ agents: ['001'], details: 'yes' }} | ${'an invalid details option'}
  `('returns 400 with $title', async ({ body }) => {
    await supertest(mockPlatformServer.getServerListener())
      .post('/reports/sca')
      .set('osd-xsrf', 'kibana')
      .send(body)
      .expect(400);

    expect(addScaChecksToReport).not.toHaveBeenCalled();
  });

  it('rejects more agents than the report limit', async () => {
    const response = await supertest(mockPlatformServer.getServerListener())
      .post('/reports/sca')
      .set('osd-xsrf', 'kibana')
      .send({ agents: Array.from({ length: 5001 }, (_, i) => `${i}`) });

    // The mock server limits the payload to 1 KB, so the request may be
    // rejected before the schema (maxSize 5000) validates it.
    expect([400, 413]).toContain(response.status);
    expect(addScaChecksToReport).not.toHaveBeenCalled();
  });

  it('returns the indexer error', async () => {
    mockSearch.mockRejectedValue(
      Object.assign(new Error('security_exception'), {
        meta: {
          statusCode: 403,
          body: { error: { reason: 'no permissions for [indices:data/read]' } },
        },
      }),
    );

    const response = await supertest(mockPlatformServer.getServerListener())
      .post('/reports/sca')
      .set('osd-xsrf', 'kibana')
      .send({ agents: ['001'] })
      .expect(403);

    expect(response.body.message).toContain(
      'no permissions for [indices:data/read]',
    );
  });
});
