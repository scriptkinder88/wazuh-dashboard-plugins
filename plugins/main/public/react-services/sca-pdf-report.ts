import { PLUGIN_PLATFORM_REQUEST_HEADERS } from '../../common/constants';
import { normalizeScaReportAgentIds } from './sca-report-context';

export const SCA_PDF_REPORT_ENDPOINT = '/reports/sca';

export interface ScaPdfReportOptions {
  /** Include the per-server tables with every control. */
  details?: boolean;
}

const FILENAME_PATTERN = /filename="?([^";]+)"?/i;

export const getScaReportFilename = (
  contentDisposition: string | null | undefined,
  now: Date = new Date(),
) =>
  FILENAME_PATTERN.exec(contentDisposition || '')?.[1] ||
  `wazuh-sca-${(now.getTime() / 1000) | 0}.pdf`;

const getErrorMessage = async (response: Response) => {
  try {
    const body = await response.json();
    return body?.message || response.statusText;
  } catch {
    return response.statusText || `Request failed (${response.status})`;
  }
};

/**
 * Requests the server-side SCA PDF report of the selected agents.
 *
 * The platform HTTP client reads every non-JSON response as text, which
 * corrupts a PDF, so the binary body is read with `fetch` directly.
 */
export const requestScaPdfReport = async (
  agentIds: string[] | string,
  options: ScaPdfReportOptions,
  { prependBasePath }: { prependBasePath: (path: string) => string },
  fetchImplementation: typeof fetch = window.fetch.bind(window),
): Promise<{ blob: Blob; filename: string }> => {
  const agents = normalizeScaReportAgentIds(agentIds);

  if (!agents.length) {
    throw new Error('Select at least one server for the SCA report.');
  }

  const response = await fetchImplementation(
    prependBasePath(SCA_PDF_REPORT_ENDPOINT),
    {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        ...PLUGIN_PLATFORM_REQUEST_HEADERS,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ agents, details: options?.details === true }),
    },
  );

  if (!response.ok) {
    throw new Error(await getErrorMessage(response));
  }

  return {
    blob: await response.blob(),
    filename: getScaReportFilename(response.headers.get('content-disposition')),
  };
};
