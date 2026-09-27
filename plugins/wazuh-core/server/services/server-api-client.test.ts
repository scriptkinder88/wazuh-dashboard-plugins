import { Logger } from 'opensearch-dashboards/server';
import { ServerAPIClient } from './server-api-client';
import { ManageHosts } from './manage-hosts';
import { ISecurityFactory } from './security-factory';

const API_HOST = {
  id: 'default',
  url: 'https://server-api',
  port: 55000,
  username: 'wazuh-wui',
  password: 'wazuh-wui',
  run_as: false,
};

interface RequestOptions {
  headers: Record<string, unknown>;
  httpsAgent: { options: { rejectUnauthorized: boolean } };
}

interface ClientInternals {
  _buildRequestOptions: (
    method: string,
    path: string,
    data: unknown,
    options: unknown,
  ) => Promise<RequestOptions>;
}

function createClient() {
  const logger = {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  };
  const manageHosts = {
    get: jest.fn().mockResolvedValue(API_HOST),
    isEnabledAuthWithRunAs: jest.fn().mockReturnValue(false),
  };
  const dashboardSecurity = {
    getCurrentUser: jest.fn().mockResolvedValue({ username: 'admin' }),
  };
  const client = new ServerAPIClient(
    logger as unknown as Logger,
    manageHosts as unknown as ManageHosts,
    dashboardSecurity as unknown as ISecurityFactory,
  );

  return { client, logger };
}

function buildRequestOptions(client: ServerAPIClient, data: unknown) {
  return (client as unknown as ClientInternals)._buildRequestOptions(
    'GET',
    '/agents',
    data,
    { apiHostID: 'default', token: 'server-session-token' },
  );
}

describe('ServerAPIClient request security', () => {
  it('verifies API TLS certificates by default', async () => {
    const { client } = createClient();
    const options = await buildRequestOptions(client, {});

    expect(options.httpsAgent.options.rejectUnauthorized).toBe(true);
  });

  it('keeps caller headers from replacing the server Authorization token', async () => {
    const { client } = createClient();

    for (const name of ['Authorization', 'authorization', 'AUTHORIZATION']) {
      const options = await buildRequestOptions(client, {
        headers: { [name]: 'Bearer caller-token' },
      });

      expect(options.headers.Authorization).toBe('Bearer server-session-token');
      expect(JSON.stringify(options.headers)).not.toContain('caller-token');
    }
  });

  it('allows content type and drops other caller headers', async () => {
    const { client, logger } = createClient();
    const options = await buildRequestOptions(client, {
      headers: {
        'content-type': 'application/xml',
        Cookie: 'wz-token=caller-token',
      },
    });

    expect(options.headers['content-type']).toBe('application/xml');
    expect(options.headers.Cookie).toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
  });
});
