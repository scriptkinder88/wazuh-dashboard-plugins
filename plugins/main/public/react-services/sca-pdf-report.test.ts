import {
  getScaReportFilename,
  requestScaPdfReport,
  SCA_PDF_REPORT_ENDPOINT,
} from './sca-pdf-report';

const http = { prependBasePath: (path: string) => `/base${path}` };

const createResponse = ({
  ok = true,
  status = 200,
  statusText = 'OK',
  headers = {},
  json,
  blob,
}: any) => ({
  ok,
  status,
  statusText,
  headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
  json: json || (() => Promise.reject(new Error('not json'))),
  blob: blob || (() => Promise.resolve('pdf-blob')),
});

describe('SCA PDF report request', () => {
  it('reads the filename of the attachment', () => {
    expect(
      getScaReportFilename('attachment; filename="wazuh-sca-1790000000.pdf"'),
    ).toBe('wazuh-sca-1790000000.pdf');
    expect(getScaReportFilename(null, new Date(1790000000123))).toBe(
      'wazuh-sca-1790000000.pdf',
    );
  });

  it('posts the selected agents and returns the PDF', async () => {
    const fetchMock = jest.fn().mockResolvedValue(
      createResponse({
        headers: {
          'content-disposition': 'attachment; filename="wazuh-sca-1.pdf"',
        },
      }),
    );

    const result = await requestScaPdfReport(
      ['001', '002', '001'],
      { details: true },
      http,
      fetchMock,
    );

    expect(fetchMock).toHaveBeenCalledWith(`/base${SCA_PDF_REPORT_ENDPOINT}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'osd-xsrf': 'kibana', 'content-type': 'application/json' },
      body: JSON.stringify({ agents: ['001', '002'], details: true }),
    });
    expect(result).toEqual({ blob: 'pdf-blob', filename: 'wazuh-sca-1.pdf' });
  });

  it('rejects an empty selection without a request', async () => {
    const fetchMock = jest.fn();

    await expect(
      requestScaPdfReport([], { details: false }, http, fetchMock),
    ).rejects.toThrow('Select at least one server for the SCA report.');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('throws the message of an error response', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(
      createResponse({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        json: () =>
          Promise.resolve({ message: '5029 - Reporting was aborted (denied)' }),
      }),
    );

    await expect(
      requestScaPdfReport(['001'], {}, http, fetchMock),
    ).rejects.toThrow('5029 - Reporting was aborted (denied)');

    fetchMock.mockResolvedValueOnce(
      createResponse({ ok: false, status: 502, statusText: 'Bad Gateway' }),
    );
    await expect(
      requestScaPdfReport(['001'], {}, http, fetchMock),
    ).rejects.toThrow('Bad Gateway');
  });
});
