/* eslint-disable camelcase */ // Wazuh API field names
import {
  ScaReportAgentsError,
  filterAuthorizedAgentIds,
} from './sca-authorized-agents';
import { SCA_REPORT_MAX_AGENTS } from '../../../common/sca/report-limits';

const contextReturning = (ids: string[] | Error) => {
  const request = jest.fn(() => {
    if (ids instanceof Error) {
      return Promise.reject(ids);
    }
    return Promise.resolve({
      data: { data: { affected_items: ids.map(id => ({ id })) } },
    });
  });
  return {
    request,
    context: { wazuh: { api: { client: { asCurrentUser: { request } } } } },
  };
};

describe('filterAuthorizedAgentIds', () => {
  it('asks the API as the current user for the requested agents', async () => {
    const { context, request } = contextReturning(['001', '002']);
    await filterAuthorizedAgentIds(context, ['001', '002', '001'], 'api');
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/agents',
      {
        params: { agents_list: '001,002', select: 'id', limit: 2 },
      },
      { apiHostID: 'api' },
    );
  });

  it('drops the agents the user cannot read', async () => {
    const { context } = contextReturning(['003', '001']);
    await expect(
      filterAuthorizedAgentIds(context, ['001', '002', '003'], 'api'),
    ).resolves.toEqual(['001', '003']);
  });

  it('accepts a single agent id', async () => {
    const { context } = contextReturning(['001']);
    await expect(
      filterAuthorizedAgentIds(context, '001', 'api'),
    ).resolves.toEqual(['001']);
  });

  it('fails when no requested agent is readable', async () => {
    const { context } = contextReturning([]);
    await expect(
      filterAuthorizedAgentIds(context, ['001'], 'api'),
    ).rejects.toThrow(ScaReportAgentsError);
  });

  it('fails when the API rejects the request', async () => {
    const { context } = contextReturning(new Error('forbidden'));
    await expect(
      filterAuthorizedAgentIds(context, ['001'], 'api'),
    ).rejects.toThrow('forbidden');
  });

  it('refuses empty and oversized selections without calling the API', async () => {
    const { context, request } = contextReturning([]);
    await expect(filterAuthorizedAgentIds(context, [], 'api')).rejects.toThrow(
      /No agent selected/,
    );
    const many = Array.from({ length: SCA_REPORT_MAX_AGENTS + 1 }, (_, i) =>
      String(i + 1).padStart(3, '0'),
    );
    await expect(
      filterAuthorizedAgentIds(context, many, 'api'),
    ).rejects.toThrow(/at most/);
    expect(request).not.toHaveBeenCalled();
  });
});
